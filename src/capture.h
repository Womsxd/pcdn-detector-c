/* capture.h —— AF_PACKET 环形缓冲抓包与报文解析 */
#ifndef PCDN_CAPTURE_H
#define PCDN_CAPTURE_H

#include "config.h"
#include "detector.h"

typedef struct capturer capturer;

capturer *capturer_create(const char *iface, bool promisc, const config_t *cfg, detector *det,
                          char *err, size_t errlen);
void capturer_destroy(capturer *c);
int capturer_run(capturer *c, char *err, size_t errlen);
void capturer_stop(capturer *c);
int capturer_reconfigure(capturer *c, const config_t *cfg, bool promisc, char *err,
                         size_t errlen);

#endif
