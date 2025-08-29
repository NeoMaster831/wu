void __fastcall sub_559EBC002ED2(Node *a1)
{
  _QWORD *content; // r12
  size_t **v2; // rbx

  a1->fd->fd->fd->content = (size_t)malloc(0x30u) + 16;
  content = (_QWORD *)a1->fd->fd->fd->content;
  v2 = (size_t **)a1->fd->fd->fd->fd->content;
  *(content - 1) = 49;
  *content = *(_QWORD *)**v2;
  content[1] = v2;
  content[2] = (unsigned __int8)*(_QWORD *)(**v2 + 16) | ((*v2)[2] << 8);
  content[3] = (*v2)[3] + *(_QWORD *)(**v2 + 24);
  if ( *(_QWORD *)**v2 )
    *(_QWORD *)(*(_QWORD *)**v2 + 8LL) = content;
  a1->fd->fd->content = **v2;
}