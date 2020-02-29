#ifndef _HIDE_H
#define _HIDE_H

int hide_module(const char *name);
void unhide_module(const char *name);

int hide_init(void);
void hide_exit(void);

#endif
