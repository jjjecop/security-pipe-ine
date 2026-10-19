class FakeRedis:
    # จำลองคำสั่ง list ของ Redis ที่คิวใช้ เก็บไว้ใน dict ธรรมดา ไม่ต้องเปิด Redis จริง
    def __init__(self):
        self.lists = {}

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