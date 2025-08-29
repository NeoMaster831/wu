void __fastcall sub_559EBC00579B(Node *a1)
{
  char *content; // rbx
  char *v2; // rdi
  size_t *p_content; // rsi
  __int64 i; // rcx

  content = (char *)a1->fd->fd->fd->fd->fd->content;
  v2 = &content[sprintf(content, "%.251s", content)];
  p_content = &a1->content;
  for ( i = 1; i; --i )
  {
    *(_DWORD *)v2 = *(_DWORD *)p_content;
    p_content = (size_t *)((char *)p_content + 4);
    v2 += 4;
  }
}