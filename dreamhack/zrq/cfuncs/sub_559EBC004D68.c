void __fastcall sub_559EBC004D68(Node *a1)
{
  tcgetattr(0, (struct termios *)a1->fd->content);
  LODWORD(a1->fd->fd->fd->fd->fd->content) = *(_DWORD *)(a1->fd->content + 12);
  *(_DWORD *)(a1->fd->content + 12) &= 0xFFFFFFF5;
  tcsetattr(0, 0, (const struct termios *)a1->fd->content);
  free((void *)a1->content);
}