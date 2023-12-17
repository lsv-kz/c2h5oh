#ifndef CLASS_STRING_H_
#define CLASS_STRING_H_

#include <iostream>
#include <string>
//======================================================================
class String
{
    char *buf;
    int buf_size;
    int len;
    unsigned int ind_ = 0;
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
    void append(char ch)
    {
        if (buf_size <= (len + 1))
        {
            if (reserve(buf_size + 32))
            {
                return;
            }
        }
        
        buf[len] = ch;
        len++;
        buf[len] = 0;
    }
    //------------------------------------------------------------------
    void append(const char *s)
    {
        if (!s) return;
        for (int i = 0; *(s + i); ++i)
        {
            if (buf_size <= (len + 1))
            {
                if (reserve(buf_size + 64))
                {
                    return;
                }
            }
            
            buf[len] = *(s + i);
            ++len;
            buf[len] = 0;
        }
    }
    //------------------------------------------------------------------
    void append(char *s)
    {
        if (!s) return;
        
        for (int i = 0; *(s + i); ++i)
        {
            if (buf_size <= (len + 1))
            {
                if (reserve(buf_size + 64))
                {
                    return;
                }
            }
            
            buf[len] = *(s + i);
            ++len;
            buf[len] = 0;
        }
    }
    //------------------------------------------------------------------
    void append(const std::string& s)
    {
        int n = s.size();
        if (buf_size <= (len + n))
        {
            if (reserve(buf_size + n + 32))
            {
                return;
            }
        }
        
        memcpy(buf + len, s.c_str(), n);
        len += n;
        buf[len] = 0;
    }
    //------------------------------------------------------------------
    void append(const String& s)
    {
        int n = s.size();
        if (buf_size <= (len + n))
        {
            if (reserve(buf_size + n + 32))
            {
                return;
            }
        }
        
        memcpy(buf + len, s.c_str(), n);
        len += n;
        buf[len] = 0;
    }
    //------------------------------------------------------------------
    template <typename T>
    void append(T t)
    {
        const unsigned long size_ = 21;
        char s[size_];
        int cnt, minus = (t < 0) ? 1 : 0;
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
        append(s + cnt);
    }
    //------------------------------------------------------------------
    int get_part_str(char *s, int max_len)
    {
        if (err)
            return (err = 1);
        unsigned int len = buf_size;
        for (; ind_ < len; ++ind_)
            if (!is_space(buf[ind_]))
                break;

        int i = 0;
        for ( ; (i < max_len) && (ind_ < len); ind_++)
        {
            char c = buf[ind_];
            if (c == '\r')
                continue;

            if (is_space(c))
            {
                s[i] = 0;
                return 0;
            }

            if ((!isdigit(c)) && (c != '-'))
                return (err = 2);

            s[i++] = c;
        }

        s[i] = 0;
        if ((ind_ < len) && (!is_space(buf[ind_])))
        {
            fprintf(stderr, "<%s:%d> \"We are not here. It is not us.\"\n", __func__, __LINE__);
            return (err = 4);
        }

        return 0;
    }

public:
    String(){ buf = NULL; buf_size = len = err = 0; ind_ = 0; }
    explicit String(unsigned int n) { buf = NULL; buf_size = len = err = 0; ind_ = 0; reserve(n); }
    String& operator >> (double&) = delete;
    String& operator >> (char*) = delete;
    String(const String&) = delete;
    //------------------------------------------------------------------
    /*String(const String& s)
    {
        if (s.buf)
        {
            buf = new(std::nothrow) char [s.buf_size];
            if (buf)
            {
                memcpy(buf, s.buf, s.len + 1);
            }
        }
        else
            buf = NULL;
    }*/
    //------------------------------------------------------------------
    ~String()
    {
        if (buf)
        {
            delete [] buf;
        }
    }
    //------------------------------------------------------------------
    String & operator = (const char *s)
    {
        ind_ = 0; err = 0;
        if (s)
        {
            clear();
            append(s);
        }
        return *this;
    }
    //------------------------------------------------------------------
    String & operator = (const std::string& s)
    {
        ind_ = 0; err = 0;
        clear();
        append(s);
        return *this;
    }
    //------------------------------------------------------------------
    String& operator = (const String& s)
    {
        ind_ = 0; err = 0;
        clear();
        append(s.buf);
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
    const char operator[] (unsigned int n) const
    {
        if (n >= (unsigned int)buf_size) return '\0';
        return buf[n];
    }
    //------------------------------------------------------------------
    String& operator << (const String & s)
    {
        append(s);
        return *this;
    }
    //------------------------------------------------------------------
    template <typename T>
    String& operator << (T t)
    {
        ind_ = 0;
        append(t);
        return *this;
    }
    //------------------------------------------------------------------
    String& operator >> (String& s)
    {
        s.clear();
        unsigned int len = buf_size;
        for (; ind_ < len; ++ind_)
            if (!is_space(buf[ind_]))
                break;

        for (; ind_ < len; ind_++)
        {
            char c = buf[ind_];
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

        for (; ind_ < len; ++ind_)
            if (!is_space(buf[ind_]))
                break;

        for (; ind_ < len; ++ind_)
        {
            char c = buf[ind_];
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

        if (buf[ind_] != '-')
            max_len = 19;

        if (get_part_str(s, max_len) == 0)
        {
    //std::cout << " s   [" << s << "]\n";
            ll = strtoll(s, NULL, 10);
        }
        return *this;
    }
    //------------------------------------------------------------------
    String& operator >> (long& li)
    {
        li = 0;
        int max_len = 11;
        char s[12];

        if (buf[ind_] != '-')
            max_len = 10;

        if (get_part_str(s, max_len) == 0)
            li = strtol(s, NULL, 10);
        return *this;
    }
    //------------------------------------------------------------------
    String& operator >> (int& li)
    {
        li = 0;
        int max_len = 11;
        char s[12];

        if (buf[ind_] != '-')
            max_len = 10;

        if (get_part_str(s, max_len) == 0)
            li = strtol(s, NULL, 10);
        return *this;
    }
    //------------------------------------------------------------------
    String& operator >> (unsigned int& li)
    {
        li = 0;
        int max_len = 11;
        char s[12];

        if (buf[ind_] != '-')
            max_len = 10;

        if (get_part_str(s, max_len) == 0)
            li = strtol(s, NULL, 10);
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
    int reserve(int n)
    {
        if (buf_size >= n) return 0;
        char *tmp_buf = new(std::nothrow) char [n];
        if (!tmp_buf)
        {
            err = 1;
            return -1;
        }
        
        if (buf)
        {
            memcpy(tmp_buf, buf, len + 1);
            delete [] buf;
        }
        buf = tmp_buf;
        buf_size = n;
        return 0;
    }
    //------------------------------------------------------------------
    int size() const { return len; }
    
    int capacity() const { return buf_size; }
    
    void reduce(int n)
    {
        if (n >= len)
            return;
        len = n;
        buf[len] = 0;
    }
    //------------------------------------------------------------------
    const String& str() const
    {
        return *this;
    }
    //------------------------------------------------------------------
    void clear()
    {
        len = 0;
        if (buf) buf[len] = 0;
        ind_ = 0; err = 0;
    }
    //------------------------------------------------------------------
    int error() const { return err; }
};

#endif
