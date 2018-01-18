_IO_size_t
_IO_default_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{
  const char *s = (char *) data;
  _IO_size_t more = n;
  if (more <= 0)
    return 0;
  for (;;)
    {
      /* Space available. */
      if (f->_IO_write_ptr < f->_IO_write_end)
	{
	  _IO_size_t count = f->_IO_write_end - f->_IO_write_ptr;
	  if (count > more)
	    count = more;
	  if (count > 20)
	    {
#ifdef _LIBC
	      f->_IO_write_ptr = __mempcpy (f->_IO_write_ptr, s, count);
#else
	      memcpy (f->_IO_write_ptr, s, count);
	      f->_IO_write_ptr += count;
#endif
	      s += count;
	    }
	  else if (count)
	    {
	      char *p = f->_IO_write_ptr;
	      _IO_ssize_t i;
	      for (i = count; --i >= 0; )
		*p++ = *s++;
	      f->_IO_write_ptr = p;
	    }
	  more -= count;
	}
      if (more == 0 || _IO_OVERFLOW (f, (unsigned char) *s++) == EOF)
	break;
      more--;
    }
  return n - more;
}
libc_hidden_def (_IO_default_xsputn)
