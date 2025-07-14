#include <bits/stdc++.h>

using namespace std;
#define int long long

typedef complex<double> base;

void fft(vector<base> &a, bool inv) {
    int n = (int)a.size();
    for (int i = 1, j = 0; i < n; i++) {
        int bit = n >> 1;
        while (!((j ^= bit) & bit)) bit >>= 1;
        if (i < j) swap(a[i], a[j]);
    }
    for (int i = 1; i < n; i <<= 1) {
        double x = (inv ? 1 : -1) * M_PI / i;
        base w = { cos(x), sin(x) };
        for (int j = 0; j < n; j += i << 1) {
            base th(1);
            for (int k = 0; k < i; k++) {
                base tmp = a[i + j + k] * th;
                a[i + j + k] = a[j + k] - tmp;
                a[j + k] += tmp;
                th *= w;
            }
        }
    }
    if (inv) {
        for (int i = 0; i < n; i++) a[i] /= n;
    }
}

vector<int> multiply(vector<int> &A, vector<int> &B) {
    vector<base> a(A.begin(), A.end());
    vector<base> b(B.begin(), B.end());
    int n = 1;
    for (int i = 0; n <= max(a.size(), b.size()); i++) n *= 2;
    n *= 2;

    a.resize(n);	b.resize(n);
    fft(a, false);	fft(b, false);

    for (int i = 0; i < n; i++)
        a[i] *= b[i];
    fft(a, false);

    vector<int> ret(n);
    for (int i = 0; i < n; i++)
        ret[i] = (int)round(a[i].real());
    return ret;
}

signed main() {
    vector<int> av, bv;
	for(int i=0;i<60;i++) av.push_back(1);
    for(int i=0;i < 51;i++) bv.push_back(2);
    bv.push_back(1);
    bv.push_back(2);
    bv.push_back(2);
    bv.push_back(1);
    bv.push_back(1);
    bv.push_back(1);
    bv.push_back(2);
    bv.push_back(2);
    
    cout << bv.size() << endl;
    auto res = multiply(av, bv);
    for (int i = av.size() + bv.size() - 2; i > 0; i--) {
        res[i - 1] += res[i] / 2;
        res[i] %= 2;
    }

    cout << res[0];
    for (int i = 1; i < av.size() + bv.size() - 1; i++) {
        cout << res[i];
    }
    cout << '\n';
}