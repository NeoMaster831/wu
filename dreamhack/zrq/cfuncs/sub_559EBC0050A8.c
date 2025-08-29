void __fastcall sub_559EBC0050A8(Node *a1)
{
  if ( !a1->fd->fd->fd->content )
    **(_BYTE **)(a1->fd->fd->fd->fd->fd->fd->fd->content + 8 * a1->fd->fd->content) = 0;
}