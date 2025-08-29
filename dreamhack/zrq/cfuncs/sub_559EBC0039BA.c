void __fastcall sub_559EBC0039BA(Node *a1)
{
  Node *fd; // rbx

  fd = a1->fd->fd->fd->fd->fd;
  fd->content = (size_t)a1->fd;
  fd->fd->fd->fd->fd->fd->content = 1;
}