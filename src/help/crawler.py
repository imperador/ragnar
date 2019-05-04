# -*- coding: utf-8 -*-
# filename: crawler.py

import sqlite3  
import urllib2  
from HTMLParser import HTMLParser  
from urlparse import urlparse


class HREFParser(HTMLParser):  
    """
    Parser that extracts hrefs
    """
    hrefs = set()
    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            dict_attrs = dict(attrs)
            if dict_attrs.get('href'):
                self.hrefs.add(dict_attrs['href'])


def get_local_links(html, domain):  
    """
    Read through HTML content and returns a tuple of links
    internal to the given domain
    """
    hrefs = set()
    parser = HREFParser()
    parser.feed(html)
    for href in parser.hrefs:
        u_parse = urlparse(href)
        if href.startswith('/'):
            # purposefully using path, no query, no hash
            hrefs.add(u_parse.path)
        else:
          # only keep the local urls
          if u_parse.netloc == domain:
            hrefs.add(u_parse.path)
    return hrefs


class CrawlerCache(object):  
    """
    Crawler data caching per relative URL and domain.
    """
    def __init__(self, db_file):
        self.conn = sqlite3.connect(db_file)
        c = self.conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS sites
            (domain text, url text, content text)''')
        self.conn.commit()
        self.cursor = self.conn.cursor()

    def set(self, domain, url, data):
        """
        store the content for a given domain and relative url
        """
        self.cursor.execute("INSERT INTO sites VALUES (?,?,?)",
            (domain, url, data))
        self.conn.commit()

    def get(self, domain, url):
        """
        return the content for a given domain and relative url
        """
        self.cursor.execute("SELECT content FROM sites WHERE domain=? and url=?",
            (domain, url))
        row = self.cursor.fetchone()
        if row:
            return row[0]

    def get_urls(self, domain):
        """
        return all the URLS within a domain
        """
        self.cursor.execute("SELECT url FROM sites WHERE domain=?", (domain,))
        # could use fetchone and yield but I want to release
        # my cursor after the call. I could have create a new cursor tho.
        # ...Oh well
        return [row[0] for row in self.cursor.fetchall()]


class Crawler(object):  
    def __init__(self, cache=None, depth=2):
        """
        depth: how many time it will bounce from page one (optional)
        cache: a basic cache controller (optional)
        """
        self.depth = depth
        self.content = {}
        self.cache = cache

    def crawl(self, url, no_cache=None):
        """
        url: where we start crawling, should be a complete URL like
        'http://www.intel.com/news/'
        no_cache: function returning True if the url should be refreshed
        """
        u_parse = urlparse(url)
        self.domain = u_parse.netloc
        self.content[self.domain] = {}
        self.scheme = u_parse.scheme
        self.no_cache = no_cache
        self._crawl([u_parse.path], self.depth)

    def set(self, url, html):
        self.content[self.domain][url] = html
        if self.is_cacheable(url):
            self.cache.set(self.domain, url, html)

    def get(self, url):
        page = None
        if self.is_cacheable(url):
          page = self.cache.get(self.domain, url)
        if page is None:
          page = self.curl(url)
        else:
          print "cached url... [%s] %s" % (self.domain, url)
        return page

    def is_cacheable(self, url):
        return self.cache and self.no_cache \
            and not self.no_cache(url)

    def _crawl(self, urls, max_depth):
        n_urls = set()
        if max_depth:
            for url in urls:
                # do not crawl twice the same page
                if url not in self.content:
                    html = self.get(url)
                    self.set(url, html)
                    n_urls = n_urls.union(get_local_links(html, self.domain))
            self._crawl(n_urls, max_depth-1)

    def curl(self, url):
        """
        return content at url.
        return empty string if response raise an HTTPError (not found, 500...)
        """
        try:
            print "retrieving url... [%s] %s" % (self.domain, url)
            req = urllib2.Request('%s://%s%s' % (self.scheme, self.domain, url))
            response = urllib2.urlopen(req)
            return response.read().decode('ascii', 'ignore')
        except urllib2.HTTPError, e:
            print "error [%s] %s: %s" % (self.domain, url, e)
            return ''