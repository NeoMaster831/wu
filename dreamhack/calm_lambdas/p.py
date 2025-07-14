import math

class P:
    """
    삼각함수 형태로 복소수를 표현하는 클래스
    P(theta) = (cos(theta), sin(theta))
    """
    def __init__(self, cos_theta, sin_theta):
        self.cos_theta = cos_theta
        self.sin_theta = sin_theta
    
    def __str__(self):
        return f"P(cos={self.cos_theta}, sin={self.sin_theta})"
    
    def __repr__(self):
        return self.__str__()
    
    def __mul__(self, other):
        """
        복소수 곱셈: P(theta1) * P(theta2) = P(theta1 + theta2)
        삼각함수 덧셈 법칙 사용:
        cos(a+b) = cos(a)cos(b) - sin(a)sin(b)
        sin(a+b) = sin(a)cos(b) + cos(a)sin(b)
        """
        if isinstance(other, (int, float)):
            # 실수배는 각도 스케일링으로 처리
            return self.scale_angle(other)
        
        return P(
            self.cos_theta * other.cos_theta - self.sin_theta * other.sin_theta,
            self.sin_theta * other.cos_theta + self.cos_theta * other.sin_theta
        )
    
    def __rmul__(self, other):
        """실수 * P 연산 지원"""
        if isinstance(other, (int, float)):
            return self.scale_angle(other)
        return self * other
    
    def scale_angle(self, n):
        """
        각도를 n배로 스케일링 (P(n*theta) 계산)
        체비셰프 다항식 접근법이나 재귀적 계산 대신 
        간단한 케이스들을 직접 처리
        """
        if n == 0:
            return P(1, 0)  # P(0) = (1, 0)
        elif n == 1:
            return P(self.cos_theta, self.sin_theta)  # 그대로 반환
        elif n == 2:
            # P(2*theta) 계산: 배각 공식 사용
            return P(
                self.cos_theta**2 - self.sin_theta**2,  # cos(2θ) = cos²(θ) - sin²(θ)
                2 * self.cos_theta * self.sin_theta     # sin(2θ) = 2sin(θ)cos(θ)
            )
        elif n == -1:
            # P(-theta) 계산
            return P(self.cos_theta, -self.sin_theta)
        else:
            # 일반적인 경우: 현재 각도에서 변환 후 계산
            theta = math.atan2(self.sin_theta, self.cos_theta)
            new_theta = n * theta
            return P(math.cos(new_theta), math.sin(new_theta))
    
    def __add__(self, other):
        """복소수 덧셈: 단순히 각 성분을 더함"""
        return P(
            self.cos_theta + other.cos_theta,
            self.sin_theta + other.sin_theta
        )
    
    def __sub__(self, other):
        """복소수 뺄셈: 단순히 각 성분을 뺌"""
        return P(
            self.cos_theta - other.cos_theta,
            self.sin_theta - other.sin_theta
        )
    
    def conjugate(self):
        """복소수 켤레: P(theta)의 켤레는 P(-theta)"""
        return P(self.cos_theta, -self.sin_theta)
    
    def magnitude(self):
        """복소수의 크기 (모듈러스)"""
        return math.sqrt(self.cos_theta**2 + self.sin_theta**2)
    
    def angle(self):
        """복소수의 편각 (아크탄젠트 사용)"""
        return math.atan2(self.sin_theta, self.cos_theta)
    
    @classmethod
    def from_angle(cls, theta):
        """각도로부터 P 객체 생성"""
        return cls(math.cos(theta), math.sin(theta))
    
    @classmethod
    def from_complex(cls, z):
        """일반 복소수로부터 P 객체 생성"""
        r = abs(z)
        theta = math.atan2(z.imag, z.real)
        return cls(math.cos(theta), math.sin(theta))


# 사용 예시
if __name__ == "__main__":
    # 각도 π/4 (45도)의 복소수
    p1 = P.from_angle(math.pi/4)
    print(f"p1: {p1}")
    
    # 각도 π/3 (60도)의 복소수
    p2 = P.from_angle(math.pi/3)
    print(f"p2: {p2}")
    
    # 복소수 곱셈 (각도 덧셈)
    p3 = p1 * p2
    print(f"p1 * p2: {p3}")
    print(f"예상 각도: {p1.angle() + p2.angle()}")
    print(f"실제 각도: {p3.angle()}")
    
    # 각도 2배 계산
    p4 = 2 * p1
    print(f"2 * p1: {p4}")
    print(f"예상 각도: {2 * p1.angle()}")
    print(f"실제 각도: {p4.angle()}")
    
    # 복소수 덧셈
    p5 = p1 + p2
    print(f"p1 + p2: {p5}")