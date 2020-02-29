#ifndef _HOOK_H
#define _HOOK_H

int hook_init(void);
void hook_exit(void);

void *insert_function(ulong addr, ulong payload);
void uninsert_function(ulong addr);

void *replace_function(ulong addr, ulong payload);
void unreplace_function(ulong addr);

void *make_orig_func(const int *orig_func);
void unmake_orig_func(void *func);

void dump_hook_infos(void);

#endif
