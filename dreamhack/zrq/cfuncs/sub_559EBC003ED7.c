void __fastcall sub_559EBC003ED7(Node *a1)
{
  Node *fd; // rbx

  fd = a1->fd->fd->fd->fd;
  *(_BYTE *)fd->content = *((_BYTE *)&a1->content + ((unsigned __int8)fd->fd->fd->fd->content >> 4));
  *(_BYTE *)(fd->content + 1) = *((_BYTE *)&a1->content + (fd->fd->fd->fd->content & 0xF));
  fd->content += 2LL;
  free(&off_559EBC20CA50);
}