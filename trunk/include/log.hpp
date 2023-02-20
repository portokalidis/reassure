#ifndef LOG_HPP
#define LOG_HPP

#define DBGLOG ERRLOG

static inline void ERRLOG(stringstream &sstr)
{
	LOG(sstr.str());
	cerr << sstr.str();
	sstr.str("");
}

static inline void ERRLOG(const char *s)
{
	LOG(s);
	cerr << s;
}

static inline void OUTLOG(stringstream &sstr)
{
	LOG(sstr.str());
	sstr.str("");
}

static inline void OUTLOG(const char *s)
{
	LOG(s);
}

#endif
