#include "libioP.h"

_IO_size_t
_IO_fread (void *buf, _IO_size_t size, _IO_size_t count, _IO_FILE *fp)
{
  _IO_size_t bytes_requested = size * count;
  _IO_size_t bytes_read;
  CHECK_FILE (fp, 0);
  if (bytes_requested == 0)
    return 0;
  _IO_acquire_lock (fp);
  bytes_read = _IO_sgetn (fp, (char *) buf, bytes_requested);
  _IO_release_lock (fp);
  return bytes_requested == bytes_read ? count : bytes_read / size;
}
libc_hidden_def (_IO_fread)

#ifdef weak_alias
weak_alias (_IO_fread, fread)

# ifndef _IO_MTSAFE_IO
strong_alias (_IO_fread, __fread_unlocked)
libc_hidden_def (__fread_unlocked)
weak_alias (_IO_fread, fread_unlocked)
# endif
#endif
