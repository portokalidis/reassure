#ifndef REASSURE_H
#define REASSURE_H

typedef enum EXIT_STATUS_ENUM { ES_SUCCESS, ES_TIMEOUT, ES_SKIP } exis_status_t;


void log_exec_status(exis_status_t status, INT32 code);

#endif
