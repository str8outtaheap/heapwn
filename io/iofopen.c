#include "libioP.h"
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#ifdef _LIBC
# include <shlib-compat.h>
#else
# define _IO_new_fopen fopen
#endif

_IO_FILE *
__fopen_maybe_mmap (_IO_FILE *fp)
{
#ifdef _G_HAVE_MMAP
  if ((fp->_flags2 & _IO_FLAGS2_MMAP) && (fp->_flags & _IO_NO_WRITES))
    {
      /* Since this is read-only, we might be able to mmap the contents
	 directly.  We delay the decision until the first read attempt by
	 giving it a jump table containing functions that choose mmap or
	 vanilla file operations and reset the jump table accordingly.  */

      if (fp->_mode <= 0)
	_IO_JUMPS_FILE_plus (fp) = &_IO_file_jumps_maybe_mmap;
      else
	_IO_JUMPS_FILE_plus (fp) = &_IO_wfile_jumps_maybe_mmap;
      fp->_wide_data->_wide_vtable = &_IO_wfile_jumps_maybe_mmap;
    }
#endif
  return fp;
}


_IO_FILE *
__fopen_internal (const char *filename, const char *mode, int is32)
{
  struct locked_FILE
  {
    struct _IO_FILE_plus fp;
#ifdef _IO_MTSAFE_IO
    _IO_lock_t lock;
#endif
    struct _IO_wide_data wd;
  } *new_f = (struct locked_FILE *) malloc (sizeof (struct locked_FILE));

  if (new_f == NULL)
    return NULL;
#ifdef _IO_MTSAFE_IO
  new_f->fp.file._lock = &new_f->lock;
#endif
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  _IO_no_init (&new_f->fp.file, 0, 0, &new_f->wd, &_IO_wfile_jumps);
#else
  _IO_no_init (&new_f->fp.file, 1, 0, NULL, NULL);
#endif
  _IO_JUMPS (&new_f->fp) = &_IO_file_jumps;
  _IO_file_init (&new_f->fp);
#if  !_IO_UNIFIED_JUMPTABLES
  new_f->fp.vtable = NULL;
#endif
  if (_IO_file_fopen ((_IO_FILE *) new_f, filename, mode, is32) != NULL)
    return __fopen_maybe_mmap (&new_f->fp.file);

  _IO_un_link (&new_f->fp);
  free (new_f);
  return NULL;
}

_IO_FILE *
_IO_new_fopen (const char *filename, const char *mode)
{
  return __fopen_internal (filename, mode, 1);
}
