#pragma once
#include "console.hh"

// enum OutputLevel
// 	{
// 		out_trace,
// 		out_info,
// 		out_warn,
// 		out_error,
// 		out_panic,
// 	};
#define panic(info,args...) k_printer.k_panic( __FILE__, __LINE__, info,##args )
#define printf(info,args...) k_printer.print(info,##args)
#define assert(expr, detail, args...) ((expr) ? (void)0 : k_printer.assrt(__FILE__, __LINE__, #expr, detail, ##args))


#ifndef COLOR_PRINT
#define COLOR_PRINT

#define printfRed(format, ...) k_printer.print("\33[1;31m" format "\33[0m", ##__VA_ARGS__)
#define printfGreen(format, ...) k_printer.print("\33[1;32m" format "\33[0m", ##__VA_ARGS__)
#define printfBlue(format, ...) k_printer.print("\33[1;34m" format "\33[0m", ##__VA_ARGS__)
#define printfCyan(format, ...) k_printer.print("\33[1;36m" format "\33[0m", ##__VA_ARGS__)
#define printfYellow(format, ...) k_printer.print("\33[1;33m" format "\33[0m", ##__VA_ARGS__)
#define printfWhite(format, ...) k_printer.print("\33[1;37m" format "\33[0m", ##__VA_ARGS__)
#define printfMagenta(format, ...) k_printer.print("\33[1;35m" format "\33[0m", ##__VA_ARGS__)
// Info print macros
#define Info(fmt, ...) printfYellow("[INFO] => " fmt "", ##__VA_ARGS__)
#define Info_R(fmt, ...) printfRed("[INFO] => " fmt "", ##__VA_ARGS__)

// TODO macro
#define TODO(x) 
#endif

class Printer
{
    private:
		enum out_type
		{
			console,
			file,
			device,
		};
        out_type _type;
		Console *	_console;
        SpinLock		_lock;
		int					_locking  = 1;
		int					_panicked = 0;
		static int	_trace_flag;
		static char _lower_digits[];
		static char _upper_digits[];
    public:
        Printer() {}
    
		void init();
        inline int is_panic() { return _panicked; }
    
		void print( const char *fmt, ... );
        void printint( int xx, int base, int sign );
		void printbyte( uint8 x );
		void printptr( uint64 x );

		static void k_panic( const char *f, uint l, const char *info, ... );
		static void panic_va( const char *f, uint l, const char *info, va_list ap );
		static void error( const char *f, uint l, const char *info, ... );
		static void error_va( const char *f, uint l, const char *info, va_list ap );
		static void warn( const char *f, uint l, const char *info, ... );
		static void warn_va( const char *f, uint l, const char *info, va_list ap );
		static void info( const char *f, uint l, const char *info, ... );
		static void info_va( const char *f, uint l, const char *info, va_list ap );
		static void trace( const char *f, uint l, const char *info, ... );
		static void trace_va( const char *f, uint l, const char *info, va_list ap );
		static void assrt( const char *f, uint l, const char *expr, const char *detail, ... );
		static void assrt_va( const char *f, uint l, const char *expr, const char *detail,
							  va_list ap );
		private:
		int _divide( ulong &n, int base )
		{
			int res = (int) ( n % base );
			n		= n / base;
			return res;
		}
    
		bool _is_number( char c ) { return (unsigned) ( c - '0' ) < 10; }
    
		int	 _to_number( char c ) { return c - '0'; }
    
};
extern Printer k_printer;


