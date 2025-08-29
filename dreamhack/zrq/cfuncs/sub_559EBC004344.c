void __fastcall sub_559EBC004344(Node *a1)
{
  signed __int64 v1; // rax
  int v2; // ebx
  _UNKNOWN *****v3; // rax

  v1 = sys_getdents(a1->content, (struct linux_dirent *)a1->fd->fd->content, 0x100u);
  v2 = v1;
  if ( (int)v1 <= 0 )
  {
    if ( (_DWORD)v1 )
      v3 = &off_559EBC20C060;
    else
      v3 = (_UNKNOWN *****)&off_559EBC20BCA0;
    free(v3);
  }
  a1->fd->fd->fd->fd->fd->fd->content = a1->fd->fd->content + v2;
  a1->fd->fd->fd->fd->fd->fd->fd->content = a1->fd->fd->content;
}