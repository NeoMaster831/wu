void __fastcall sub_559EBC0036FA(Node *a1)
{
  unsigned __int64 v1; // rax
  size_t v2; // rbx

  _BitScanReverse64(&v1, a1->fd->fd->content);
  LOBYTE(a1->fd->content) = (v1 ^ 0x3F) - 55;
  v2 = a1->fd->fd->content & 1;
  a1->fd->fd->content <<= LOBYTE(a1->fd->content);
  if ( !v2 )
    a1->fd->fd->content |= (1 << LOBYTE(a1->fd->content)) - 1;
}