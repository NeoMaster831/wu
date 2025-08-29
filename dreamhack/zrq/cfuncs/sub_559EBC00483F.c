void __fastcall sub_559EBC00483F(Node *a1)
{
  _BYTE *v1; // rbx
  unsigned __int8 v2; // r12

  v1 = *(_BYTE **)(a1->fd->fd->fd->fd->fd->content + 8 * a1->fd->fd->content);
  v2 = byte_559EBC20B660[15 * a1->fd->content + a1->fd->fd->content];
  if ( v2 )
  {
    if ( *v1 )
    {
      a1->content = dword_559EBC20B260[v2] + dword_559EBC20B260[(unsigned __int8)*v1];
      free(&off_559EBC20C900);
    }
  }
}