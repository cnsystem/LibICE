#include "ice.h"
#include <pjlib.h>
#include <pjlib-util.h>
#include <pjnath.h>
#include <stdio.h>
#include <stdlib.h>

#define THIS_FILE   "ice.cc"
typedef  struct app_t
{
    pj_bool_t used_flag;
	ice_options opt;
	pj_caching_pool cp;
	pj_pool_t *pool;
	pj_thread_t *thread;
	pj_bool_t thread_quit_flag;
	pj_ice_strans_cfg	 ice_cfg;
	pj_ice_strans *icest;
	FILE *log_fhnd;
} ice_instance;

ice_instance _instance[16];

static void _perror(const char *title, pj_status_t status)
{
	char errmsg[PJ_ERR_MSG_SIZE];
	pj_strerror(status, errmsg, sizeof(errmsg));
	PJ_LOG(1, (THIS_FILE, "%s: %s", title, errmsg));
}

static void cb_on_rx_data(pj_ice_strans *ice_st,
	unsigned comp_id,
	void *pkt, pj_size_t size,
	const pj_sockaddr_t *src_addr,
	unsigned src_addr_len)
{
	char ipstr[PJ_INET6_ADDRSTRLEN + 10];

	PJ_UNUSED_ARG(ice_st);
	PJ_UNUSED_ARG(src_addr_len);
	PJ_UNUSED_ARG(pkt);

	// Don't do this! It will ruin the packet buffer in case TCP is used!
	//((char*)pkt)[size] = '\0';

	PJ_LOG(3, (THIS_FILE, "Component %d: received %d bytes data from %s: \"%.*s\"",
		comp_id, size,
		pj_sockaddr_print(src_addr, ipstr, sizeof(ipstr), 3),
		(unsigned)size,
		(char*)pkt));
}

#define CHECK(expr)	status=expr; \
if (status != PJ_SUCCESS) {\
	_perror(#expr, status); \
	return status; \
}


static void cb_on_ice_complete(pj_ice_strans *ice_st,
	pj_ice_strans_op op,
	pj_status_t status)
{
	const char *opname =
		(op == PJ_ICE_STRANS_OP_INIT ? "initialization" :
		(op == PJ_ICE_STRANS_OP_NEGOTIATION ? "negotiation" : "unknown_op"));

	if (status == PJ_SUCCESS) {
		PJ_LOG(3, (THIS_FILE, "ICE %s successful", opname));
	}
	else {
		char errmsg[PJ_ERR_MSG_SIZE];

		pj_strerror(status, errmsg, sizeof(errmsg));
		PJ_LOG(1, (THIS_FILE, "ICE %s failed: %s", opname, errmsg));
		pj_ice_strans_destroy(ice_st);
		icedemo.icest = NULL;
	}
}

static void log_func(int level, const char *data, int len)
{
	pj_log_write(level, data, len);
	if (icedemo.log_fhnd) {
		if (fwrite(data, len, 1, icedemo.log_fhnd) != 1)
			return;
	}
}

static pj_status_t handle_events(unsigned max_msec, unsigned *p_count)
{
	enum { MAX_NET_EVENTS = 1 };
	pj_time_val max_timeout = { 0, 0 };
	pj_time_val timeout = { 0, 0 };
	unsigned count = 0, net_event_count = 0;
	int c;

	max_timeout.msec = max_msec;

	timeout.sec = timeout.msec = 0;
	c = pj_timer_heap_poll(icedemo.ice_cfg.stun_cfg.timer_heap, &timeout);
	if (c > 0)
		count += c;


	pj_assert(timeout.sec >= 0 && timeout.msec >= 0);
	if (timeout.msec >= 1000) timeout.msec = 999;


	if (PJ_TIME_VAL_GT(timeout, max_timeout))
		timeout = max_timeout;


	do {
		c = pj_ioqueue_poll(icedemo.ice_cfg.stun_cfg.ioqueue, &timeout);
		if (c < 0) {
			pj_status_t err = pj_get_netos_error();
			pj_thread_sleep(PJ_TIME_VAL_MSEC(timeout));
			if (p_count)
				*p_count = count;
			return err;
		}
		else if (c == 0) {
			break;
		}
		else {
			net_event_count += c;
			timeout.sec = timeout.msec = 0;
		}
	} while (c > 0 && net_event_count < MAX_NET_EVENTS);

	count += net_event_count;
	if (p_count)
		*p_count = count;

	return PJ_SUCCESS;
}

static int _worker_thread(void *unused)
{
	PJ_UNUSED_ARG(unused);

	while (!icedemo.thread_quit_flag) {
		handle_events(500, NULL);
	}

	return 0;
}

static void _set_server(pj_str_t serv, pj_str_t *host, pj_uint16_t *port)
{
	char *pos;
	if ((pos = pj_strchr(&icedemo.opt.turn_srv, ':')) != NULL) {
		host->ptr = icedemo.opt.turn_srv.ptr;
		host->slen = (pos - icedemo.opt.turn_srv.ptr);
		*port = (pj_uint16_t)atoi(pos + 1);
	}
	else {
		*host = icedemo.opt.turn_srv;
		*port = PJ_STUN_PORT;
	}
}
static pj_status_t  _lib_init()
{
	pj_status_t status;
	CHECK(pj_init());
	CHECK(pjlib_util_init());
	CHECK(pjnath_init());
	return status;
}
static pj_status_t _create_instance(pj_ice_strans_cfg cfg, unsigned comp_cnt, pj_ice_strans **handle)
{
	pj_ice_strans_cb icecb;
	pj_status_t status;
	pj_ice_strans *icest = NULL;
	
	pj_assert(handle!=NULL);
	pj_bzero(&icecb, sizeof(icecb));
	icecb.on_rx_data = cb_on_rx_data;
	icecb.on_ice_complete = cb_on_ice_complete;
	status = pj_ice_strans_create("icedemo", &cfg, comp_cnt, NULL, &icecb, &icest);
	if (status != PJ_SUCCESS)
		_perror("error creating ice", status);
	else
		PJ_LOG(3, (THIS_FILE, "ICE instance successfully created"));
	*handle = icest;
	return status;
}
static void _destroy_instance(pj_ice_strans *handle)
{	
	pj_assert(handle != NULL);
	pj_ice_strans_destroy(handle);
	PJ_LOG(3, (THIS_FILE, "ICE instance destroyed"));
}
static pj_status_t _init_session(pj_ice_strans *handle, unsigned rolechar)
{
	pj_ice_sess_role role = (pj_tolower((pj_uint8_t)rolechar) == 'o' ? PJ_ICE_SESS_ROLE_CONTROLLING : PJ_ICE_SESS_ROLE_CONTROLLED);
	pj_status_t status;

	assert(handle != NULL);
	if (pj_ice_strans_has_sess(handle)) {
		PJ_LOG(1, (THIS_FILE, "Error: Session already created"));
		return -1;
	}
	status = pj_ice_strans_init_ice(handle, role, NULL, NULL);
	if (status != PJ_SUCCESS)
		_perror("error creating session", status);
	else
		PJ_LOG(3, (THIS_FILE, "ICE session created"));
	pj_ice_strans_state state;
	while ((state = pj_ice_strans_get_state(icedemo.icest)) != PJ_ICE_STRANS_STATE_SESS_READY)
		pj_thread_sleep(10);
	return status;
}
static pj_status_t _stop_session(pj_ice_strans *handle)
{
	pj_status_t status;
	pj_assert(handle != NULL);
	if (!pj_ice_strans_has_sess(handle)) {
		PJ_LOG(1, (THIS_FILE, "Error: No ICE session, initialize first"));
		return -1;
	}
	status = pj_ice_strans_stop_ice(handle);
	if (status != PJ_SUCCESS)
		_perror("error stopping session", status);
	else
		PJ_LOG(3, (THIS_FILE, "ICE session stopped"));
	return status;
}
static pj_status_t _start_nego(pj_ice_strans *handle, unsigned comp_cnt, cand_info retmote)
{
	pj_str_t rufrag, rpwd;
	pj_status_t status;

	pj_assert(handle != NULL);
	pj_assert(comp_cnt == 0);
	if (!pj_ice_strans_has_sess(handle)) {
		PJ_LOG(1, (THIS_FILE, "Error: No ICE session, initialize first"));
		return -1;
	}
	PJ_LOG(3, (THIS_FILE, "Starting ICE negotiation.."));
	status = pj_ice_strans_start_ice(handle, pj_cstr(&rufrag, retmote.ufrag), pj_cstr(&rpwd, retmote.pwd), retmote.cand_cnt, retmote.cand);
	if (status != PJ_SUCCESS)
		_perror("Error starting ICE", status);
	else
		PJ_LOG(3, (THIS_FILE, "ICE negotiation started"));
	return status;
}
/*
static pj_status_t _set_remote(void *remote, cand_info* candinfo)
{
	pj_status_t status;
	char* ip;
	short port;
	int af;
	while (42)
	{	
		if (strchr(ip, ':'))
			af = pj_AF_INET6();
		else
			af = pj_AF_INET();
		pj_sockaddr_init(af, &candinfo->def_addr[1], NULL, 0);
		status = pj_sockaddr_set_str_addr(af, &candinfo->def_addr[1], &pj_str(ip));
		if (status != PJ_SUCCESS) {
			PJ_LOG(1, (THIS_FILE, "Invalid IP address"));
			break;
		}
		pj_sockaddr_set_port(&candinfo->def_addr[1], (pj_uint16_t)port);
	}
	return status;
}
*/

int ice_init(ice_options config)
{
	pj_status_t status;

	if (config.log_file) {
		icedemo.log_fhnd = fopen(icedemo.opt.log_file, "a");
		pj_log_set_log_func(&log_func);
	}
	CHECK(_lib_init());
	memcpy(&icedemo.opt, &config, sizeof(config));
	pj_caching_pool_init(&icedemo.cp, NULL, 0);
	pj_ice_strans_cfg_default(&icedemo.ice_cfg);
	icedemo.ice_cfg.stun_cfg.pf = &icedemo.cp.factory;
	icedemo.pool = pj_pool_create(&icedemo.cp.factory, "icedemo", 512, 512, NULL);
	CHECK(pj_timer_heap_create(icedemo.pool, 100, &icedemo.ice_cfg.stun_cfg.timer_heap));
	CHECK(pj_ioqueue_create(icedemo.pool, 16, &icedemo.ice_cfg.stun_cfg.ioqueue));
	CHECK(pj_thread_create(icedemo.pool, "icedemo", &_worker_thread, NULL, 0, 0, &icedemo.thread));
	icedemo.ice_cfg.af = pj_AF_INET();
	if (icedemo.opt.ns.slen) {
		CHECK(pj_dns_resolver_create(&icedemo.cp.factory, "resolver", 0, icedemo.ice_cfg.stun_cfg.timer_heap, icedemo.ice_cfg.stun_cfg.ioqueue, &icedemo.ice_cfg.resolver));
		CHECK(pj_dns_resolver_set_ns(icedemo.ice_cfg.resolver, 1, &icedemo.opt.ns, NULL));
	}
	if (icedemo.opt.max_host != -1)
		icedemo.ice_cfg.stun.max_host_cands = icedemo.opt.max_host;
	icedemo.ice_cfg.opt.aggressive = icedemo.opt.regular ? PJ_FALSE : PJ_TRUE;
	if (icedemo.opt.stun_srv.slen)
	{
		_set_server(icedemo.opt.stun_srv, &icedemo.ice_cfg.stun.server, &icedemo.ice_cfg.stun.port);		
		icedemo.ice_cfg.stun.cfg.ka_interval = 300;
	}
	if (icedemo.opt.turn_srv.slen) {
		_set_server(icedemo.opt.stun_srv, &icedemo.ice_cfg.turn.server, &icedemo.ice_cfg.turn.port);
		icedemo.ice_cfg.turn.auth_cred.type = PJ_STUN_AUTH_CRED_STATIC;
		icedemo.ice_cfg.turn.auth_cred.data.static_cred.username = icedemo.opt.turn_username;
		icedemo.ice_cfg.turn.auth_cred.data.static_cred.data_type = PJ_STUN_PASSWD_PLAIN;
		icedemo.ice_cfg.turn.auth_cred.data.static_cred.data = icedemo.opt.turn_password;
		icedemo.ice_cfg.turn.conn_type = icedemo.opt.turn_tcp ? PJ_TURN_TP_TCP : PJ_TURN_TP_UDP;
		icedemo.ice_cfg.turn.alloc_param.ka_interval = 300;
	}
	return PJ_SUCCESS;
}

int ice_release(void)
{
	PJ_LOG(3, (THIS_FILE, "ICE Library release.."));
	if (icedemo.icest)
		pj_ice_strans_destroy(icedemo.icest);

	pj_thread_sleep(500);

	icedemo.thread_quit_flag = PJ_TRUE;
	if (icedemo.thread) {
		pj_thread_join(icedemo.thread);
		pj_thread_destroy(icedemo.thread);
	}

	if (icedemo.ice_cfg.stun_cfg.ioqueue)
		pj_ioqueue_destroy(icedemo.ice_cfg.stun_cfg.ioqueue);

	if (icedemo.ice_cfg.stun_cfg.timer_heap)
		pj_timer_heap_destroy(icedemo.ice_cfg.stun_cfg.timer_heap);

	pj_caching_pool_destroy(&icedemo.cp);

	pj_shutdown();

	if (icedemo.log_fhnd) {
		fclose(icedemo.log_fhnd);
		icedemo.log_fhnd = NULL;
	}
	return PJ_SUCCESS;
}

void ice_send_data(unsigned comp_id, const char *data)
{
	pj_status_t status;

	if (icedemo.icest == NULL) {
		PJ_LOG(1, (THIS_FILE, "Error: No ICE instance, create it first"));
		return;
	}

	if (!pj_ice_strans_has_sess(icedemo.icest)) {
		PJ_LOG(1, (THIS_FILE, "Error: No ICE session, initialize first"));
		return;
	}
	if (comp_id<1 || comp_id>pj_ice_strans_get_running_comp_cnt(icedemo.icest)) {
		PJ_LOG(1, (THIS_FILE, "Error: invalid component ID"));
		return;
	}
	const pj_ice_sess_check* session = pj_ice_strans_get_valid_pair(icedemo.icest, comp_id);
	status = pj_ice_strans_sendto(icedemo.icest, comp_id, data, strlen(data), &session->rcand->addr, pj_sockaddr_get_len(&session->rcand->addr));
	if (status != PJ_SUCCESS)
		_perror("Error sending data", status);
	else
		PJ_LOG(3, (THIS_FILE, "Data sent"));
}

void ice_get_local_cand(cand_info* cands)
{
	pj_str_t local_ufrag, local_pwd;	
	pj_bzero(cands, sizeof(cand_info));
	if (icedemo.icest == NULL)
	{
		_create_instance(icedemo.ice_cfg, icedemo.opt.comp_cnt, &icedemo.icest);
		_init_session(icedemo.icest, 'o');
	}	
	pj_ice_strans_get_ufrag_pwd(icedemo.icest, &local_ufrag, &local_pwd, NULL, NULL);
	memcpy(cands->ufrag, local_ufrag.ptr, local_ufrag.slen+1);
	memcpy(cands->pwd, local_pwd.ptr, local_pwd.slen + 1);
	for (unsigned i = 1; i <= icedemo.opt.comp_cnt; i++)
	{
		unsigned count = 0;
		pj_ice_strans_enum_cands(icedemo.icest, i, &count, cands->cand + cands->cand_cnt);
		cands->cand_cnt += count;
		cands->def_addr[i] = cands->cand[0].addr;
	}
	cands->comp_cnt = icedemo.opt.comp_cnt;
}

int ice_start_session(cand_info retmote)
{
	pj_status_t status;
	if (icedemo.icest == NULL)
	{
		_create_instance(icedemo.ice_cfg, icedemo.opt.comp_cnt, &icedemo.icest);
		_init_session(icedemo.icest, 'o');
	}
	CHECK(_start_nego(icedemo.icest, icedemo.opt.comp_cnt, retmote));
	return status;
}

int ice_stop_session(void)
{
	pj_status_t status;
	CHECK(_stop_session(icedemo.icest));
	_destroy_instance(icedemo.icest);
	return status;
}

