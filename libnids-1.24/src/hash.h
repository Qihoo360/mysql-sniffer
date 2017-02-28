#ifndef _HASH_H_
#define _HAHS_H_

#include <glib.h>

# ifdef __cplusplus
extern "C" {
# endif
void init_hash();
u_int mkhash (u_int , u_short , u_int , u_short);


guint tuple4_hash (gconstpointer key);
gboolean tuple4_equal (gconstpointer a, gconstpointer b);
# ifdef __cplusplus
}
# endif

#endif
