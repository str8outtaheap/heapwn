#include <stdlib.h>
#include "libioP.h"
#include <string.h>
#include <errno.h>

/* Read up to (and including) a TERMINATOR from FP into *LINEPTR
   (and null-terminate it).  *LINEPTR is a pointer returned from malloc (or
   NULL), pointing to *N characters of space.  It is realloc'ed as
   necessary.  Returns the number of characters read (not including the
   null terminator), or -1 on error or EOF.  */

_IO_ssize_t
_IO_getdelim (lineptr, n, delimiter, fp)
     char **lineptr;
     _IO_size_t *n;
     int delimiter;
     _IO_FILE *fp;
{
  _IO_ssize_t result;
  _IO_ssize_t cur_len = 0;
  _IO_ssize_t len;

  if (lineptr == NULL || n == NULL)
    {
      MAYBE_SET_EINVAL;
      return -1;
    }
  CHECK_FILE (fp, -1);
  _IO_acquire_lock (fp);
  if (_IO_ferror_unlocked (fp))
    {
      result = -1;
      goto unlock_return;
    }

  if (*lineptr == NULL || *n == 0)
    {
      *n = 120;
      *lineptr = (char *) malloc (*n);
      if (*lineptr == NULL)
	{
	  result = -1;
	  goto unlock_return;
	}
    }

  len = fp->_IO_read_end - fp->_IO_read_ptr;
  if (len <= 0)
    {
      if (__underflow (fp) == EOF)
	{
	  result = -1;
	  goto unlock_return;
	}
      len = fp->_IO_read_end - fp->_IO_read_ptr;
    }

  for (;;)
    {
      _IO_size_t needed;
      char *t;
      t = (char *) memchr ((void *) fp->_IO_read_ptr, delimiter, len);
      if (t != NULL)
	len = (t - fp->_IO_read_ptr) + 1;
      if (__builtin_expect (cur_len + len + 1 < 0, 0))
	{
	  __set_errno (EOVERFLOW);
	  result = -1;
	  goto unlock_return;
	}
      /* Make enough space for len+1 (for final NUL) bytes.  */
      needed = cur_len + len + 1;
      if (needed > *n)
	{
	  char *new_lineptr;

	  if (needed < 2 * *n)
	    needed = 2 * *n;  /* Be generous. */
	  new_lineptr = (char *) realloc (*lineptr, needed);
	  if (new_lineptr == NULL)
	    {
	      result = -1;
	      goto unlock_return;
	    }
	  *lineptr = new_lineptr;
	  *n = needed;
	}
      memcpy (*lineptr + cur_len, (void *) fp->_IO_read_ptr, len);
      fp->_IO_read_ptr += len;
      cur_len += len;
      if (t != NULL || __underflow (fp) == EOF)
	break;
      len = fp->_IO_read_end - fp->_IO_read_ptr;
    }
  (*lineptr)[cur_len] = '\0';
  result = cur_len;

unlock_return:
  _IO_release_lock (fp);
  return result;
}

#ifdef weak_alias
weak_alias (_IO_getdelim, __getdelim)
weak_alias (_IO_getdelim, getdelim)
#endif
