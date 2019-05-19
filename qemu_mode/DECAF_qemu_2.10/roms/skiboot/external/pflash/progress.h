#ifndef __PROGRESS_H
#define __PROGRESS_H

void progress_init(unsigned long count);
void progress_tick(unsigned long cur);
void progress_end(void);

#endif /* __PROGRESS_H */
