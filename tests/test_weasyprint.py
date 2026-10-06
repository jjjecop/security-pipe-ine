from weasyprint import HTML

html_content = """
<html>
<head>
<style>
body { font-family: sans-serif; }
h1 { color: navy; }
</style>
</head>
<body>
<h1>ทดสอบ WeasyPrint</h1>
</body>
</html>

"""

HTML(string=html_content).write_pdf("test_output.pdf")
print("สร้าง PDF สำเร็จ!")