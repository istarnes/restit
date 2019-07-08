import re

from django.db.models import Q

def normalize_query(query_string,
                    findterms=re.compile(r'"([^"]+)"|(\S+)').findall,
                    normspace=re.compile(r'\s{2,}').sub):
    ''' Splits the query string in invidual keywords, getting rid of unecessary spaces
        and grouping quoted words together.
        Example:

        >>> normalize_query('  some random  words "with   quotes  " and   spaces')
        ['some', 'random', 'words', 'with quotes', 'and', 'spaces']

    '''
    return [normspace(' ', (t[0] or t[1]).strip()) for t in findterms(query_string)]

def get_query(query_string, search_fields, value_fields=[], default_filter="icontains"):
    ''' Returns a query, that is a combination of Q objects. That combination
        aims to search keywords within a model by testing the given search fields.

    '''
    query = None # Query to search for every search term
    terms = normalize_query(query_string)
    for term in terms:
        or_query = None # Query to search for a given term in each field
        for field_name in value_fields:
            filter = "icontains"
            if term.startswith('<='):
                filter = "lte"
                value = term[2:]
            elif term.startswith('>='):
                filter = "gte"
                value = term[2:]
            elif term.startswith('<'):
                filter = "lt"
                value = term[1:]
            elif term.startswith('>'):
                filter = "gt"
                value = term[1:]
            elif term.startswith("=="):
                filter = "iexact"
                value = term[2:]
            else:
                filter = "icontains"
                value = term
            # print "{0}__{1}".format(field_name, filter)
            # print value
            q = Q(**{"{0}__{1}".format(field_name, filter): value})
            if or_query is None:
               or_query = q
            else:
               or_query = or_query | q
        for field_name in search_fields:
            q = Q(**{"{0}__{1}".format(field_name, default_filter): term})
            if or_query is None:
                or_query = q
            else:
                or_query = or_query | q
        if query is None:
            query = or_query
        else:
            query = query & or_query
    return query
