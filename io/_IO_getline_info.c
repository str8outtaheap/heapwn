_IO_size_t
_IO_getline_info (fp, buf, n, delim, extract_delim, eof)
     _IO_FILE *fp;
     char *buf;
     _IO_size_t n;
     int delim;
     int extract_delim;
     int *eof;
{
  char *ptr = buf;
  if (eof != NULL)
    *eof = 0;
  if (__builtin_expect (fp->_mode, -1) == 0)
    _IO_fwide (fp, -1);
  while (n != 0)
    {
      _IO_ssize_t len = fp->_IO_read_end - fp->_IO_read_ptr;
      if (len <= 0)
	{
	  int c = __uflow (fp);
	  if (c == EOF)
	    {
	      if (eof)
		*eof = c;
	      break;
	    }
	  if (c == delim)
	    {
 	      if (extract_delim > 0)
		*ptr++ = c;
	      else if (extract_delim < 0)
		_IO_sputbackc (fp, c);
	      if (extract_delim > 0)
		++len;
	      return ptr - buf;
	    }
	  *ptr++ = c;
	  n--;
	}
      else
	{
	  char *t;
	  if ((_IO_size_t) len >= n)
	    len = n;
	  t = (char *) memchr ((void *) fp->_IO_read_ptr, delim, len);
	  if (t != NULL)
	    {
	      _IO_size_t old_len = ptr-buf;
	      len = t - fp->_IO_read_ptr;
	      if (extract_delim >= 0)
		{
		  ++t;
		  if (extract_delim > 0)
		    ++len;
		}
	      memcpy ((void *) ptr, (void *) fp->_IO_read_ptr, len);
	      fp->_IO_read_ptr = t;
	      return old_len + len;
	    }
	  memcpy ((void *) ptr, (void *) fp->_IO_read_ptr, len);
	  fp->_IO_read_ptr += len;
	  ptr += len;
	  n -= len;
	}
    }
  return ptr - buf;
}
