
try:
    import pdfkit
except:
    pdfkit = None


def html_to_pdf(html):
    """
    pdfkit.from_url('http://google.com', 'out.pdf')
    pdfkit.from_file('test.html', 'out.pdf')
    pdfkit.from_string('Hello!', 'out.pdf')
    """
    return html
