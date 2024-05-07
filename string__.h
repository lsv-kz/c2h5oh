#ifndef CLASS_STRING_H_
#define CLASS_STRING_H_

#include <iostream>
#include <string>
//======================================================================
class String
{
    char *buf;
    unsigned int buf_size;
    unsigned int buf_len;
    unsigned int index_ = 0;
    int err = 0;
    //------------------------------------------------------------------
    int is_space(char c)
    {
        switch (c)
        {
            case '\x20':
            case '\t':
            case '\r':
            case '\n':
            case '\0':
                return 1;
        }
        return 0;
    }
    //------------------------------------------------------------------
    int is_float(char c)
    {
        switch (c)
        {
            case '.':
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                return 1;
        }
        return 0;
    }
    //------------------------------------------------------------------
    void append(const char ch)
    {
        if (buf_size <= (buf_len + 1))
        {
            if (reserve(buf_len + 32))
                return;
        }
        
        buf[buf_len++] = ch;
        buf[buf_len] = 0;
    }
    //------------------------------------------------------------------
    void append(const char *s)
    {
        if (!s)
            return;
        append(s, strlen(s));
    }
    //------------------------------------------------------------------
    void append(const char *s, unsigned int len)
    {
        if (!s)
            return;
        if (buf_size <= (buf_len + len))
        {
            if (reserve(buf_len + len + 32))
                return;
        }

        memcpy(buf + buf_len, s, len);
        buf_len += len;
        buf[buf_len] = 0;
    }
    //------------------------------------------------------------------
    void append(const std::string& s)
    {
        append(s.c_str(), s.size());
    }
    //------------------------------------------------------------------
    void append(const String& s)
    {
        append(s.buf, s.buf_len);
    }
    //------------------------------------------------------------------
    template <typename T>
    void append(T t)
    {
        const unsigned long size_ = 21;
        char s[size_];
        unsigned int cnt, minus = (t < 0) ? 1 : 0;
        const char *get_char = "9876543210123456789";

        cnt = 20;

        s[cnt] = 0;
        while (cnt > 0)
        {
            --cnt;
            s[cnt] = get_char[9 + (t % 10)];
            t /= 10;

            if (t == 0)
                break;
        }

        if (minus)
            s[--cnt] = '-';
        append(s + cnt, size_ - cnt - 1);
    }
    //------------------------------------------------------------------
    int get_part_str(char *s, unsigned int max_len)
    {
        if (err)
            return (err = 1);
        for (; index_ < buf_len; ++index_)
            if (!is_space(buf[index_]))
                break;

        unsigned int i = 0;
        for ( ; (i < max_len) && (index_ < buf_len); index_++)
        {
            char c = buf[index_];
            if (c == '\r')
                continue;

            if (is_space(c))
            {
                s[i] = 0;
                return 0;
            }

            s[i++] = c;
        }

        s[i] = 0;

        return 0;
    }
    //------------------------------------------------------------------
    void init()
    {
        buf = NULL;
        buf_size = buf_len = err = 0; index_ = 0;
    }

public:
    String() { init(); }
    explicit String(unsigned int n) { init(); reserve(n); }
    String& operator >> (double&) = delete;
    String& operator >> (char*) = delete;
    String(const String&) = delete;
    String(const char *s) { init(); append(s); }
    //------------------------------------------------------------------
    /*String(const String& s)
    {
        init();
        if (s.buf)
        {
            int n = s.buf_len + 1 + 32;
            if (reserve(n))
                return;
            append(s.buf, s.buf_len);
            buf_size = n;
        }
    }*/
    //------------------------------------------------------------------
    ~String()
    {
        if (buf)
            delete [] buf;
    }
    //------------------------------------------------------------------
    String & operator = (const char *s)
    {
        clear();
        if (s)
            append(s);
        return *this;
    }
    //------------------------------------------------------------------
    String & operator = (const std::string& s)
    {
        clear();
        append(s);
        return *this;
    }
    //------------------------------------------------------------------
    String& operator = (const String& s)
    {
        clear();
        append(s.buf, s.buf_len);
        return *this;
    }
    //------------------------------------------------------------------
    friend bool operator == (const String& s1, const char *s2)
    {
        if (!strcmp(s1.buf,s2))
            return true;
        else
            return false;
    }
    //------------------------------------------------------------------
    friend bool operator != (const String& s1, const char *s2)
    {
        if (s1 == s2)
            return false;
        else
            return true;
    }
    //------------------------------------------------------------------
    String & operator += (char c)
    {
        append(c);
        return *this;
    }
    //------------------------------------------------------------------
    String & operator += (const char *s)
    {
        append(s);
        return *this;
    }
    //------------------------------------------------------------------
    String & operator += (const String& s)
    {
        append(s);
        return *this;
    }
    //------------------------------------------------------------------
    const char operator[] (unsigned int n) const
    {
        if (n >= (unsigned int)buf_size)
            return '\0';
        return buf[n];
    }
    //------------------------------------------------------------------
    String& operator << (const char ch)
    {
        append(ch);
        return *this;
    }
    //------------------------------------------------------------------
    String& operator << (const char* s)
    {
        append(s);
        return *this;
    }
    //------------------------------------------------------------------
    String& operator << (char* s)
    {
        append((const char*)s);
        return *this;
    }
    //------------------------------------------------------------------
    String& operator << (const String& s)
    {
        append(s);
        return *this;
    }
    //------------------------------------------------------------------
    String& operator << (const std::string& s)
    {
        append(s);
        return *this;
    }

    template <typename T>
    String& operator << (const T t)
    {
        append(t);
        return *this;
    }
    //------------------------------------------------------------------
    String& operator >> (String& s)
    {
        s.clear();
        unsigned int len = buf_size;
        for (; index_ < len; ++index_)
            if (!is_space(buf[index_]))
                break;

        for (; index_ < len; index_++)
        {
            char c = buf[index_];
            if (is_space(c))
                break;
            s += c;
        }
        return *this;
    }
    //------------------------------------------------------------------
    String& operator >> (std::string& s)
    {
        s.clear();
        unsigned int len = buf_size;

        for (; index_ < len; ++index_)
            if (!is_space(buf[index_]))
                break;

        for (; index_ < len; ++index_)
        {
            char c = buf[index_];
            if (is_space(c))
                break;
            s += c;
        }
        return *this;
    }
    //------------------------------------------------------------------
    String& operator >> (long long& ll)
    {
        ll = 0;
        int max_len = 20;
        char s[21];

        for (; (index_ < buf_len); ++index_)
            if (!is_space(buf[index_]))
                break;
        if (buf[index_] != '-')
            max_len = 19;

        if (get_part_str(s, max_len) == 0)
        {
            char *p;
            ll = strtoll(s, &p, 10);
            if (!p)
            {
                err = 1;
                ll = 0;
            }
            else
                index_ -= strlen(p);
        }
        return *this;
    }
    //------------------------------------------------------------------
    String& operator >> (long& li)
    {
        li = 0;
        int max_len = 11;
        char s[12];

        for (; (index_ < buf_len); ++index_)
            if (!is_space(buf[index_]))
                break;
        if (buf[index_] != '-')
            max_len = 10;

        if (get_part_str(s, max_len) == 0)
        {
            char *p;
            li = strtol(s, &p, 10);
            if (!p)
            {
                err = 1;
                li = 0;
            }
            else
                index_ -= strlen(p);
        }
        return *this;
    }
    //------------------------------------------------------------------
    String& operator >> (int& li)
    {
        li = 0;
        int max_len = 11;
        char s[12];

        for (; (index_ < buf_len); ++index_)
            if (!is_space(buf[index_]))
                break;
        if (buf[index_] != '-')
            max_len = 10;

        if (get_part_str(s, max_len) == 0)
        {
            char *p;
            li = strtol(s, &p, 10);
            if (!p)
            {
                err = 1;
                li = 0;
            }
            else
                index_ -= strlen(p);
        }
        return *this;
    }
    //------------------------------------------------------------------
    String& operator >> (unsigned int& li)
    {
        li = 0;
        int max_len = 11;
        char s[12];

        for (; (index_ < buf_len); ++index_)
            if (!is_space(buf[index_]))
                break;
        if (buf[index_] != '-')
            max_len = 10;

        if (get_part_str(s, max_len) == 0)
        {
            char *p;
            li = strtol(s, &p, 10);
            if (!p)
            {
                err = 1;
                li = 0;
            }
            else
                index_ -= strlen(p);
        }
        return *this;
    }
    //------------------------------------------------------------------
    const char *c_str() const
    {
        if (!buf)
            return "";
        else
            return buf;
    }
    //------------------------------------------------------------------
    int reserve(unsigned int n)
    {
        if (buf_size >= n)
            return 0;

        char *tmp_buf = new(std::nothrow) char [n];
        if (!tmp_buf)
        {
            err = 1;
            return -1;
        }

        if (buf)
        {
            memcpy(tmp_buf, buf, buf_len + 1);
            delete [] buf;
        }
        buf = tmp_buf;
        buf_size = n;

        return 0;
    }
    //------------------------------------------------------------------
    int size() const { return buf_len; }
    
    int capacity() const { return buf_size; }
    
    void reduce(unsigned int n)
    {
        if (n >= buf_len)
            return;
        buf_len = n;
        buf[buf_len] = 0;
    }
    //------------------------------------------------------------------
    const String& str() const
    {
        return *this;
    }
    //------------------------------------------------------------------
    void clear()
    {
        buf_len = index_ = err = 0;
        if (buf)
            buf[buf_len] = 0;
    }
    //------------------------------------------------------------------
    int error() const { return err; }
};

#endif
