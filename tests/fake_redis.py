class FakeRedis:
    # จำลองคำสั่ง list ของ Redis ที่คิวใช้ เก็บไว้ใน dict ธรรมดา ไม่ต้องเปิด Redis จริง
    def __init__(self):
        self.lists = {}
        self.values = {}
        self.expires_at = {}
        self.now = 0.0

    def advance(self, seconds):
        # เลื่อนเวลาของ Redis ปลอม แทนการรอจริง
        self.now += seconds
        for name, when in list(self.expires_at.items()):
            if when <= self.now:
                self.values.pop(name, None)
                del self.expires_at[name]

    def rpush(self, name, value):
        self.lists.setdefault(name, []).append(value)

    def blmove(self, first_list, second_list, timeout, src="LEFT", dest="RIGHT"):
        items = self.lists.get(first_list)
        if not items:
            return None
        value = items.pop(0)
        self.lists.setdefault(second_list, []).append(value)
        return value

    def lrem(self, name, count, value):
        items = self.lists.get(name, [])
        if value in items:
            items.remove(value)
            return 1
        return 0

    def lrange(self, name, start, end):
        return list(self.lists.get(name, []))

    def get(self, name):
        return self.values.get(name)

    def set(self, name, value, ex=None):
        self.values[name] = str(value)
        self.expires_at.pop(name, None)
        if ex is not None:
            self.expires_at[name] = self.now + ex
        return True

    def incr(self, name):
        self.values[name] = str(int(self.values.get(name, 0)) + 1)
        return int(self.values[name])

    def expire(self, name, seconds, nx=False):
        if name not in self.values or (nx and name in self.expires_at):
            return False
        self.expires_at[name] = self.now + seconds
        return True

    def delete(self, name):
        self.expires_at.pop(name, None)
        return 1 if self.values.pop(name, None) is not None else 0
