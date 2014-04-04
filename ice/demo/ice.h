#ifndef __ICE_H__
#define __ICE_H__




#ifdef __cplusplus
extern "C" {
#endif
    typedef enum ice_cand_type
    {
        ICE_CAND_TYPE_HOST,
        ICE_CAND_TYPE_SRFLX,
        ICE_CAND_TYPE_PRFLX,
        ICE_CAND_TYPE_RELAYED
    } ice_cand_type;
	typedef struct _string{
	    char* ptr;
	    long slen;
	}string;
	typedef struct ipv4
    {
        unsigned short family;
        unsigned short port;
        unsigned int s_addr;
        char sin_zero[8];
    }ipv4_addr;
    typedef struct ipv6
    {
        unsigned short family;
        unsigned short port;
        unsigned int flow_info;
        union{
            unsigned char s6_addr[16];
            unsigned int u6_addr[4];
        }sin6_addr;
        unsigned int scope;
    }ipv6_addr;
	typedef union sockaddr
    {
        unsigned short	    addr;	/**< Generic transport address.	    */
        ipv4_addr ipv4;	/**< IPv4 transport address.	    */
        ipv6_addr ipv6;	/**< IPv6 transport address.	    */
    } sockaddr;
    typedef struct ice_sess_cand
    {
        ice_cand_type	 type;
        int     		 status;
        unsigned char	 comp_id;
        unsigned char	 transport_id;
        unsigned short	 local_pref;
        string  		 foundation;
        unsigned int 	 prio;
        sockaddr		 addr;
        sockaddr		 base_addr;
        sockaddr		 rel_addr;
    } ice_sess_cand;
	typedef struct cand_info
	{
		char		 ufrag[80];
		char		 pwd[80];
		unsigned	 comp_cnt;
		sockaddr	 def_addr[4];
		unsigned	 cand_cnt;
		ice_sess_cand cand[4];
	} cand_info;
	typedef struct options
	{
		unsigned int    comp_cnt;
		string    ns;
		int			max_host;
		int   regular;
		string    stun_srv;
		string    turn_srv;
		int   turn_tcp;
		string    turn_username;
		string    turn_password;
		int   turn_fingerprint;
		const char *log_file;
	} ice_options;

	int ice_init(ice_options config);
	int ice_release(void);
	int ice_start_session(cand_info retmote);
	int ice_stop_session(void);
	void ice_send_data(unsigned comp_id, const char *data);
	void ice_get_local_cand(cand_info* cands);
#ifdef __cplusplus
}
#endif
#endif