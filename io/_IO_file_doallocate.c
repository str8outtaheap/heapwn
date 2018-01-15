int
_IO_file_doallocate (_IO_FILE *fp)
{
  _IO_size_t size;
  char *p;
  struct stat64 st;

#ifndef _LIBC
  /* If _IO_cleanup_registration_needed is non-zero, we should call the
     function it points to.  This is to make sure _IO_cleanup gets called
     on exit.  We call it from _IO_file_doallocate, since that is likely
     to get called by any program that does buffered I/O. */
  if (__glibc_unlikely (_IO_cleanup_registration_needed != NULL))
    (*_IO_cleanup_registration_needed) ();
#endif

  size = _IO_BUFSIZ;
  if (fp->_fileno >= 0 && __builtin_expect (_IO_SYSSTAT (fp, &st), 0) >= 0)
    {
      if (S_ISCHR (st.st_mode))
	{
	  /* Possibly a tty.  */
	  if (
#ifdef DEV_TTY_P
	      DEV_TTY_P (&st) ||
#endif
	      local_isatty (fp->_fileno))
	    fp->_flags |= _IO_LINE_BUF;
	}
#if _IO_HAVE_ST_BLKSIZE
      if (st.st_blksize > 0)
	size = st.st_blksize;
#endif
    }
  p = malloc (size);
  if (__glibc_unlikely (p == NULL))
    return EOF;
  _IO_setb (fp, p, p + size, 1);
  return 1;
}
libc_hidden_def (_IO_file_doallocate)
