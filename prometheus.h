typedef struct pam_call {
	char pam_funcname[51];
	void *(*pam_func)();
} s_pam_call;

s_pam_call struct_pam_auth;
