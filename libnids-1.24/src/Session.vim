let SessionLoad = 1
if &cp | set nocp | endif
let s:so_save = &so | let s:siso_save = &siso | set so=0 siso=0
let v:this_session=expand("<sfile>:p")
silent only
cd ~/work/libnids-1.24/src
if expand('%') == '' && !&modified && line('$') <= 1 && getline(1) == ''
  let s:wipebuf = bufnr('%')
endif
set shortmess=aoO
badd +220 tcp_conn_pool.c
badd +209 tcp.c
badd +458 libnids.c
badd +38 ~/work/libnids-1.24/src/util.c
badd +92 /usr/include/netinet/ip.h
badd +83 /usr/include/netinet/tcp.h
badd +64 ~/work/libnids-1.24/src/nids.h
badd +84 ~/work/libnids-1.24/src/hash.c
badd +9 ~/work/libnids-1.24/src/hash.h
badd +5 ~/work/libnids-1.24/src/tcp_conn_pool.h
argglobal
silent! argdel *
argadd tcp_conn_pool.c
edit tcp_conn_pool.c
set splitbelow splitright
set nosplitbelow
set nosplitright
wincmd t
set winheight=1 winwidth=1
argglobal
setlocal fdm=indent
setlocal fde=0
setlocal fmr={{{,}}}
setlocal fdi=#
setlocal fdl=10000
setlocal fml=1
setlocal fdn=20
setlocal fen
81
normal! zo
161
normal! zo
let s:l = 171 - ((32 * winheight(0) + 28) / 57)
if s:l < 1 | let s:l = 1 | endif
exe s:l
normal! zt
171
normal! 049|
tabnext 1
if exists('s:wipebuf')
  silent exe 'bwipe ' . s:wipebuf
endif
unlet! s:wipebuf
set winheight=1 winwidth=20 shortmess=filnxtToO
let s:sx = expand("<sfile>:p:r")."x.vim"
if file_readable(s:sx)
  exe "source " . fnameescape(s:sx)
endif
let &so = s:so_save | let &siso = s:siso_save
doautoall SessionLoadPost
let g:this_obsession = v:this_session
unlet SessionLoad
" vim: set ft=vim :
