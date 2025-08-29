void __fastcall sub_559EBC002FBB(Node *a1)
{
  *(_WORD *)a1->fd->fd->fd->fd->fd->fd->fd->content = *(_WORD *)a1->fd->fd->fd->fd->fd->content;
  a1->fd->fd->fd->content = (size_t)&off_559EBC20BFD0;
}