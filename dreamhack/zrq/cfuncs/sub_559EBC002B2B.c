void __fastcall sub_559EBC002B2B(Node *a1)
{
  char *v1; // rax

  v1 = (char *)malloc(*(_DWORD *)(a1->content + 24) >> 7);
  free(v1 + 32);
}