#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_crypt.h>
#ifdef __linux__
#include <sys/random.h>
#endif
#include "base64.c"
#include "sha256.c"

#define VERIFY_IP /* only allow one ip per challenge */
#define WORK 0x00005FFF
#define WORK_STR "0x00005FFF"

#if nginx_version < 1023000
#define LEGACY
#endif

#define shield_challenge_str "pow-shield-challenge"
ngx_str_t shield_challenge = {
	sizeof(shield_challenge_str) - 1,
	(u_char*)shield_challenge_str
};

#define shield_answer_str "pow-shield-answer"
ngx_str_t shield_answer = {
	sizeof(shield_answer_str) - 1,
	(u_char*)shield_answer_str
};

#define shield_id_str "pow-shield-id"
ngx_str_t shield_id = {
	sizeof(shield_id_str) - 1,
	(u_char*)shield_id_str
};

const char html_page[] =
"<!DOCTYPE html><html><head>"
"<meta charset=\"utf-8\"><title>PoW Shield</title>"
"</head><body>"
"<h1>PoW Shield</h1>"
"<noscript><p>Javascript required</p></noscript>"
"<p id=\"hash-rate\"></p>"
"<script>"
"function setCookie(cname, cvalue) {"
	"document.cookie = cname + \"=\" + cvalue + \";"
				"path=/;SameSite=Strict\";"
"}"
"function getCookie(cname) {"
	"let name = cname + \"=\";"
	"let ca = document.cookie.split(';');"
	"for(let i = 0; i < ca.length; i++) {"
		"let c = ca[i];"
		"while (c.charAt(0) == ' ') {"
			"c = c.substring(1);"
		"}"
		"if (c.indexOf(name) == 0) {"
			"return c.substring(name.length, c.length);"
		"}"
	"}"
	"return \"\";"
"}"
"var challenge = Uint8Array.from(atob(getCookie(\"pow-shield-challenge\")) + "
			"\"\\0\\0\\0\\0\", c => c.charCodeAt(0));"
"var hash = 0;"
"var startTime = new Date();"
"function updateHashRate() {"
	"let timeDiff = (new Date() - startTime)/1000;"
	"document.getElementById(\"hash-rate\").innerHTML =\"Hash-rate : \" +"
		"String(Math.round(hash/timeDiff)) +\" h/s\";"
"}"
"async function pow(data, i) {"
	"let bufView = new Uint32Array(data.buffer);"
	"bufView[8] = i;"
	"while (bufView[8] + 1 > -1) {"
		"let h = new Uint8Array(await "
			"crypto.subtle.digest(\"SHA-256\", data));"
		"let view32 = new Uint32Array(h.buffer);"
		"if (view32[0] <= "WORK_STR") {"
			"break;"
		"}"
		"hash++;"
		"bufView[8]++;"
	"}"
	"setCookie(\"pow-shield-answer\", bufView[8]);"
	"document.cookie = \"pow-shield-challenge=;"
		"expires=Thu, 01 Jan 1970 00:00:00 UTC;"
		"path=/;SameSite=Strict\";"
	"window.location.reload();"
"}"
"setInterval(updateHashRate, 1000);"
"pow(challenge.slice(0), 0x80000000);"
"pow(challenge, 0);"
"setTimeout(updateHashRate, 100);"
"</script>"
"</body></html>"
;

typedef struct {
	ngx_http_complex_value_t  *realm;
} ngx_http_powshield_loc_conf_t;


static ngx_int_t ngx_http_powshield_handler(ngx_http_request_t *r);
static void *ngx_http_powshield_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_powshield_merge_loc_conf(ngx_conf_t *cf,
		void *parent, void *child);
static ngx_int_t ngx_http_powshield_init(ngx_conf_t *cf);

static ngx_command_t  ngx_http_powshield_commands[] = {

	{ ngx_string("powshield"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
			|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
		ngx_http_set_complex_value_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_powshield_loc_conf_t, realm),
		NULL },

	ngx_null_command
};

static ngx_http_module_t  ngx_http_powshield_module_ctx = {
	NULL,					/* preconfiguration */
	ngx_http_powshield_init,		/* postconfiguration */
	NULL,					/* create main configuration */
	NULL,					/* init main configuration */
	NULL,					/* create server configuration */
	NULL,					/* merge server configuration */
	ngx_http_powshield_create_loc_conf,	/* create location configuration */
	ngx_http_powshield_merge_loc_conf	/* merge location configuration */
};


ngx_module_t  ngx_http_powshield_module = {
	NGX_MODULE_V1,
	&ngx_http_powshield_module_ctx,		/* module context */
	ngx_http_powshield_commands,		/* module directives */
	NGX_HTTP_MODULE,			/* module type */
	NULL,					/* init master */
	NULL,					/* init module */
	NULL,					/* init process */
	NULL,					/* init thread */
	NULL,					/* exit thread */
	NULL,					/* exit process */
	NULL,					/* exit master */
	NGX_MODULE_V1_PADDING
};

#define CHALLENGE_DATA_LENGTH 32
#define TABLE_SIZE 131072 /* needs to be a power of 2 */
#define TABLE_BITS (TABLE_SIZE - 1)
#define EXPIRATION 50 /* seconds before expiration */
#define EXPIRATION_COMPLETED 600 /* seconds before expiration when completed */
#define MAX_USAGE 200 /* usage count before invalidity */
struct pow_challenge {
	ngx_rbtree_node_t	rbnode;
	unsigned char		data[CHALLENGE_DATA_LENGTH + sizeof(uint32_t)];
	uint32_t		id;
	unsigned int		used;
	time_t			created;
	unsigned		completed:1;
#ifdef VERIFY_IP
	uint32_t		ip;
#endif
};

struct pow_tree {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
};

struct pow_tree* challenges = NULL;
ngx_pool_t  *cf_pool = NULL;

uint32_t
fnv(void *buf, size_t len)
{
	uint32_t hval = 0;
	unsigned char *bp = (unsigned char *)buf;
	unsigned char *be = bp + len;
	while (bp < be) {
		hval *= 0x01000193;
		hval ^= (uint32_t)*bp++;
	}
	return hval;
}
#define FNV(X) fnv(X, sizeof(X))

uint32_t
powshield_get_ip(ngx_http_request_t *r)
{
	struct sockaddr_in          *sin;
#if (NGX_HAVE_INET6)
	struct sockaddr_in6         *sin6;
#endif
	switch (r->connection->sockaddr->sa_family) {
	case AF_INET:
		sin = (struct sockaddr_in *) r->connection->sockaddr;
		return sin->sin_addr.s_addr;
#if (NGX_HAVE_INET6)
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
		return FNV(sin6->sin6_addr.s6_addr);
#endif
	}
	return 0;
}

struct pow_challenge
powshield_new_challenge()
{
	struct pow_challenge challenge = {0};
	challenge.created = time(NULL);
#ifdef __linux__
	if (getrandom(&challenge.id, sizeof(challenge.id), GRND_RANDOM) !=
			sizeof(challenge.id))
		challenge.id = rand();
	if (getrandom(challenge.data, sizeof(challenge.data), GRND_RANDOM) !=
			sizeof(challenge.data)) {
		for (size_t i = 0; i < sizeof(challenge.data); i++) {
			challenge.data[i] = rand();
		}
	}
#else
        arc4random_buf(&challenge.id, sizeof(challenge.id));
        arc4random_buf(challenge.data, sizeof(challenge.data));
#endif
	return challenge;
}

static int
powshield_is_expired(struct pow_challenge *challenge, time_t now)
{
	return -(now - challenge->created > (challenge->completed ?
					EXPIRATION_COMPLETED : EXPIRATION));
}

static int
powshield_insert_challenge(struct pow_challenge challenge)
{
	struct pow_challenge *cnode;
	struct pow_tree *root = &challenges[challenge.id & TABLE_BITS];
	ngx_rbtree_node_t  *node;

	cnode = ngx_palloc(cf_pool, sizeof(challenge));
	*cnode = challenge;

	node = &cnode->rbnode;
	node->key = cnode->id;

	ngx_rbtree_insert(&root->rbtree, node);
	return 0;
}

static struct pow_challenge *
powshield_get_challenge(uint32_t id)
{
	struct pow_challenge	*n;
	ngx_rbtree_t		*rbtree;
	ngx_rbtree_node_t	*node, *sentinel;

	rbtree = &challenges[id & TABLE_BITS].rbtree;
	node = rbtree->root;
	sentinel = rbtree->sentinel;

	while (node != sentinel) {

		n = (struct pow_challenge *) node;

		if (id != (uint32_t)node->key) {
			node = (id < node->key) ? node->left : node->right;
			continue;
		}

		if (powshield_is_expired(n, time(NULL)))
			return NULL;

		return n;
	}

	return NULL;
}

static int
powshield_use_challenge(struct pow_challenge *challenge)
{
	challenge->used++;
	if (challenge->used >= MAX_USAGE || time(NULL) - challenge->created >
						EXPIRATION_COMPLETED) {
		memset(challenge, 0, sizeof(*challenge));
		return -1;
	}
	return 0;
}

static int
powshield_verify_challenge(struct pow_challenge challenge, uint32_t answer)
{
	unsigned char hash[SHA256_BLOCK_SIZE];
	uint32_t *hash_u32 = (void*)hash;
	memcpy(&challenge.data[CHALLENGE_DATA_LENGTH],
			&answer, sizeof(answer));
	sha256(challenge.data, sizeof(challenge.data), hash);
	return -(*hash_u32 > WORK);
}

static int
powshield_setcookie(ngx_http_request_t *r, const char* name, const char *data,
			char *buf, size_t buflen)
{
	ngx_table_elt_t			*v;
	const char cookie[] = "%s=%s;path=/;SameSite=Strict";
	size_t len;

	v = ngx_list_push(&r->headers_out.headers);
	if (v == NULL) {
		return -1;
	}
	v->hash = rand();
	v->key.len = sizeof("Set-Cookie") - 1;
	v->key.data = (u_char *)"Set-Cookie";
	len = snprintf(buf, buflen, cookie, name, data);
	v->value.len = len;
	v->value.data = (u_char *)buf;
	return 0;
}

static u_char *
powshield_getcookie(ngx_http_request_t *r, ngx_str_t *name)
{
#ifdef LEGACY
	ngx_str_t value;
	ngx_int_t n;

	n = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, name,
						&value);
	if (n != NGX_OK) {
		return NULL;
	}
	return value.data;
#else
	ngx_str_t value;
	ngx_table_elt_t *elt;
	elt = ngx_http_parse_multi_header_lines(r, r->headers_in.cookie, name,
							&value);
	if (!elt) return NULL;
	return value.data;
#endif
}

static ngx_int_t
ngx_http_powshield_handler(ngx_http_request_t *r)
{
	ngx_http_powshield_loc_conf_t	*alcf;
	ngx_str_t			realm;
	ngx_buf_t			*b;
	ngx_chain_t			out;
	char buf[1024], base64[CHALLENGE_DATA_LENGTH * 3 + 64], idbuf[128];
	const u_char *answer = NULL, *id;
	uint32_t cid = 0;
	int len, canswer = 0;

	alcf = ngx_http_get_module_loc_conf(r, ngx_http_powshield_module);
	if (alcf->realm == NULL) {
		return NGX_DECLINED;
	}

	id = powshield_getcookie(r, &shield_id);
	if (id) {
		cid = atol((const char*)id);//, NULL, 10);
		if (!cid) id = NULL;
	}
	if (id)
		answer = powshield_getcookie(r, &shield_answer);
	if (answer)
		canswer = atoi((const char *)answer);
	while (answer) {
		struct pow_challenge *challenge = powshield_get_challenge(cid);
		if (!challenge) break;
		if (challenge->completed) {
#ifdef VERIFY_IP
			if (challenge->ip != powshield_get_ip(r))
				break;
#endif
			if (powshield_use_challenge(challenge))
				break;
			return NGX_DECLINED;
		}
		if (powshield_verify_challenge(*challenge, canswer)) break;
		challenge->completed = 1;
		return NGX_DECLINED;
	}
	if (answer)
		id = NULL;

	if (ngx_http_complex_value(r, alcf->realm, &realm) != NGX_OK) {
		return NGX_ERROR;
	}

	if (realm.len == 3 && ngx_strncmp(realm.data, "off", 3) == 0) {
		return NGX_DECLINED;
	}

	if (!id || !powshield_getcookie(r, &shield_challenge)) {

		struct pow_challenge challenge = powshield_new_challenge();
		char idtmp[32];

		len = base64_encode(challenge.data, CHALLENGE_DATA_LENGTH,
				(unsigned char*)base64, sizeof(base64));
		if (len == -1) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		snprintf(idtmp, sizeof(idtmp), "%u", challenge.id);
		if (powshield_setcookie(r, shield_id_str, idtmp,
					idbuf, sizeof(idbuf))) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		if (powshield_setcookie(r, shield_challenge_str, base64, buf,
					sizeof(buf))) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
#ifdef VERIFY_IP
		challenge.ip = powshield_get_ip(r);
#endif
		powshield_insert_challenge(challenge);
	}

	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = sizeof(html_page) - 1;
	r->headers_out.content_type.len = sizeof("text/html") - 1;
	r->headers_out.content_type.data = (u_char *) "text/html";

	ngx_http_send_header(r);

	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	if (b == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
				"Failed to allocate response buffer.");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	b->pos = (u_char*)html_page;
	b->last = (u_char*)html_page + sizeof(html_page);
	b->memory = 1; /* content is in read-only memory */
	b->last_buf = 1; /* there will be no more buffers in the request */

	out.buf = b;
	out.next = NULL;

	return ngx_http_output_filter(r, &out);
}

static void *
ngx_http_powshield_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_powshield_loc_conf_t  *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_powshield_loc_conf_t));
	if (conf == NULL) {
		return NULL;
	}

	return conf;
}

static char *
ngx_http_powshield_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_powshield_loc_conf_t  *prev = parent;
	ngx_http_powshield_loc_conf_t  *conf = child;

	if (conf->realm == NULL) {
		conf->realm = prev->realm;
	}

	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_powshield_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt        *h;
	ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_powshield_handler;

	challenges = ngx_pcalloc(cf->pool, sizeof(*challenges) * TABLE_SIZE);
	if (!challenges) {
		return NGX_ERROR;
	}
	cf_pool = cf->pool;
	for (int i = 0; i < TABLE_SIZE; i++) {
		ngx_rbtree_init(&challenges[i].rbtree, &challenges[i].sentinel,
				ngx_rbtree_insert_value);
	}

	return NGX_OK;
}
