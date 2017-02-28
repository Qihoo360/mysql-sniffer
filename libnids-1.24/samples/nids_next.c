/*
This is an example how one can use nids_getfd() and nids_next() functions.
You can replace printall.c's function main with this file.
*/

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

int
main ()
{
  // here we can alter libnids params, for instance:
  // nids_params.n_hosts=256;
  int fd;
  int time = 0;
  fd_set rset;
  struct timeval tv;

  if (!nids_init ())
  {
  	fprintf(stderr,"%s\n",nids_errbuf);
  	exit(1);
  }	
  nids_register_tcp (tcp_callback);
  fd = nids_getfd ();
  for (;;)
    {
      tv.tv_sec = 1;
      tv.tv_usec = 0;
      FD_ZERO (&rset);
      FD_SET (fd, &rset);
      // add any other fd we need to take care of
      if (select (fd + 1, &rset, 0, 0, &tv))
	{
        	if (FD_ISSET(fd,&rset)  // need to test it if there are other
        				// fd in rset
			if (!nids_next ()) break;
	}
      else
	fprintf (stderr, "%i ", time++);
    }
  return 0;
}
