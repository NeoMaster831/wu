void __fastcall sub_559EBC003486(Node *a1)
{
  Node *fd; // rbx
  _QWORD *content; // r12

  fd = a1->fd->fd->fd->fd->fd->fd->fd;
  content = (_QWORD *)fd->content;
  LOBYTE(fd->fd->fd->content) = content[4] << -(char)fd->fd->content;
  fd->fd->content += (char)fd->fd->fd->fd->content;
  *content = 0;
  free(content);
}