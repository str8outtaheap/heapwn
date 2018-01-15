_IO_off64_t
_IO_new_file_seekoff (_IO_FILE *fp, _IO_off64_t offset, int dir, int mode)
{
  _IO_off64_t result;
  _IO_off64_t delta, new_offset;
  long count;

  /* Short-circuit into a separate function.  We don't want to mix any
     functionality and we don't want to touch anything inside the FILE
     object. */
  if (mode == 0)
    return do_ftell (fp);

  /* POSIX.1 8.2.3.7 says that after a call the fflush() the file
     offset of the underlying file must be exact.  */
  int must_be_exact = (fp->_IO_read_base == fp->_IO_read_end
		       && fp->_IO_write_base == fp->_IO_write_ptr);

  bool was_writing = (fp->_IO_write_ptr > fp->_IO_write_base
		      || _IO_in_put_mode (fp));

  /* Flush unwritten characters.
     (This may do an unneeded write if we seek within the buffer.
     But to be able to switch to reading, we would need to set
     egptr to pptr.  That can't be done in the current design,
     which assumes file_ptr() is eGptr.  Anyway, since we probably
     end up flushing when we close(), it doesn't make much difference.)
     FIXME: simulate mem-mapped files. */
  if (was_writing && _IO_switch_to_get_mode (fp))
    return EOF;

  if (fp->_IO_buf_base == NULL)
    {
      /* It could be that we already have a pushback buffer.  */
      if (fp->_IO_read_base != NULL)
	{
	  free (fp->_IO_read_base);
	  fp->_flags &= ~_IO_IN_BACKUP;
	}
      _IO_doallocbuf (fp);
      _IO_setp (fp, fp->_IO_buf_base, fp->_IO_buf_base);
      _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
    }

  switch (dir)
    {
    case _IO_seek_cur:
      /* Adjust for read-ahead (bytes is buffer). */
      offset -= fp->_IO_read_end - fp->_IO_read_ptr;

      if (fp->_offset == _IO_pos_BAD)
	goto dumb;
      /* Make offset absolute, assuming current pointer is file_ptr(). */
      offset += fp->_offset;
      if (offset < 0)
	{
	  __set_errno (EINVAL);
	  return EOF;
	}

      dir = _IO_seek_set;
      break;
    case _IO_seek_set:
      break;
    case _IO_seek_end:
      {
	struct stat64 st;
	if (_IO_SYSSTAT (fp, &st) == 0 && S_ISREG (st.st_mode))
	  {
	    offset += st.st_size;
	    dir = _IO_seek_set;
	  }
	else
	  goto dumb;
      }
    }
  /* At this point, dir==_IO_seek_set. */

  /* If destination is within current buffer, optimize: */
  if (fp->_offset != _IO_pos_BAD && fp->_IO_read_base != NULL
      && !_IO_in_backup (fp))
    {
      _IO_off64_t start_offset = (fp->_offset
				  - (fp->_IO_read_end - fp->_IO_buf_base));
      if (offset >= start_offset && offset < fp->_offset)
	{
	  _IO_setg (fp, fp->_IO_buf_base,
		    fp->_IO_buf_base + (offset - start_offset),
		    fp->_IO_read_end);
	  _IO_setp (fp, fp->_IO_buf_base, fp->_IO_buf_base);

	  _IO_mask_flags (fp, 0, _IO_EOF_SEEN);
	  goto resync;
	}
    }

  if (fp->_flags & _IO_NO_READS)
    goto dumb;

  /* Try to seek to a block boundary, to improve kernel page management. */
  new_offset = offset & ~(fp->_IO_buf_end - fp->_IO_buf_base - 1);
  delta = offset - new_offset;
  if (delta > fp->_IO_buf_end - fp->_IO_buf_base)
    {
      new_offset = offset;
      delta = 0;
    }
  result = _IO_SYSSEEK (fp, new_offset, 0);
  if (result < 0)
    return EOF;
  if (delta == 0)
    count = 0;
  else
    {
      count = _IO_SYSREAD (fp, fp->_IO_buf_base,
			   (must_be_exact
			    ? delta : fp->_IO_buf_end - fp->_IO_buf_base));
      if (count < delta)
	{
	  /* We weren't allowed to read, but try to seek the remainder. */
	  offset = count == EOF ? delta : delta-count;
	  dir = _IO_seek_cur;
	  goto dumb;
	}
    }
  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base + delta,
	    fp->_IO_buf_base + count);
  _IO_setp (fp, fp->_IO_buf_base, fp->_IO_buf_base);
  fp->_offset = result + count;
  _IO_mask_flags (fp, 0, _IO_EOF_SEEN);
  return offset;
 dumb:

  _IO_unsave_markers (fp);
  result = _IO_SYSSEEK (fp, offset, dir);
  if (result != EOF)
    {
      _IO_mask_flags (fp, 0, _IO_EOF_SEEN);
      fp->_offset = result;
      _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
      _IO_setp (fp, fp->_IO_buf_base, fp->_IO_buf_base);
    }
  return result;

resync:
  /* We need to do it since it is possible that the file offset in
     the kernel may be changed behind our back. It may happen when
     we fopen a file and then do a fork. One process may access the
     file and the kernel file offset will be changed. */
  if (fp->_offset >= 0)
    _IO_SYSSEEK (fp, fp->_offset, 0);

  return offset;
}
libc_hidden_ver (_IO_new_file_seekoff, _IO_file_seekoff)
