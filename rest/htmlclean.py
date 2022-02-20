from BeautifulSoup import *

class HTMLClean(object):
    _remove = [
        'script',
        'head',
        'title',
        'applet',
        'object',
        'title',
    ]
    _ok_tags = [
        'div',
        'span',
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'address', 'blockquote', 'cite', 'code',
        'b', 'big', 'del', 'em', 'ins', 'p', 'pre', 'q', 's', 'small', 'strike', 'strong', 'sub', 'sup', 'tt', 'u', 
        'ol', 'ul', 'li',
        'dl', 'dt', 'dd',
        'br', 'hr', 
        'a',
        'table', 'tr', 'td', 'th', 'tbody', 'thead', 'tfoot', 'col', 'colgroup',
        'font',
        'style',
        'img',
        'center',
    ]
    _ok_attrs = {
        '*': [
            'id',
            'class',
            'style',
            'align',
            'background', 'bgcolor', 'color',
            'compact',
            'width', 'height',
            'name',
            'type',
            'valign',
        ],
        'a': [
            'href',
            'title',
            'rel', 'rev',
        ],
        'img': [
            'alt',
            'longdesc',
            'src',
        ],
        'td': [
            'colspan',
            'rowspan',
            'headers',
            'nowrap',
        ],
        'th': [
            'colspan',
            'rowspan',
            'headers',
            'nowrap',
        ],
        'hr': [
            'noshade',
        ],
        'ol': [
            'start',
        ],
        'li': [
            'value',
        ],
        'font': [
            'face',
            'size',
            'basefont',
        ],
    }
    
    def _clean(self, content):
        if type(content) in (Declaration,):
            return True
        if type(content) in (NavigableString,):
            return False

        if content.name.lower() in self._remove:
            return True

        removes = []
        for c in content.contents:
            if self._clean(c):
                removes.append(c)
        
        for c in removes:
            c.extract()
    
        if content.name.lower() in self._ok_tags:
            ok_attrs = self._ok_attrs['*'] + self._ok_attrs.get(content.name.lower(), [])
            removes = []
            for a in content.attrs:
                if not a[0].lower() in ok_attrs:
                    removes.append(a)
            for a in removes:
                content.attrs.remove(a)
        else:
            content.replaceWithChildren()
        
        return False

    def clean(self, data):
        soup = BeautifulSoup(data)
        removes = []
        for c in soup.contents:
            if self._clean(c):
                removes.append(c)
        
        for c in removes:
            c.extract()

        return str(soup)


