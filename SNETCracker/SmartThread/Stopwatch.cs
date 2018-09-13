using System;

namespace Amib.Threading.Internal
{
    /// <summary>
    /// Stopwatch class
    /// Used with WindowsCE and Silverlight which don't have Stopwatch
    /// </summary>
    internal class Stopwatch
    {
        private long _elapsed;
        private bool _isRunning;
        private long _startTimeStamp;

        public Stopwatch()
        {
            Reset();
        }

        private long GetElapsedDateTimeTicks()
        {
            long rawElapsedTicks = GetRawElapsedTicks();
            return rawElapsedTicks;
        }

        private long GetRawElapsedTicks()
        {
            long elapsed = _elapsed;
            if (_isRunning)
            {
                long ticks = GetTimestamp() - _startTimeStamp;
                elapsed += ticks;
            }
            return elapsed;
        }

        public static long GetTimestamp()
        {
            return DateTime.UtcNow.Ticks;
        }

        public void Reset()
        {
           _elapsed = 0L;
           _isRunning = false;
           _startTimeStamp = 0L;
        }

        public void Start()
        {
            if (!_isRunning)
            {
                _startTimeStamp = GetTimestamp();
                _isRunning = true;
            }
        }

        public static Stopwatch StartNew()
        {
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            return stopwatch;
        }

        public void Stop()
        {
            if (_isRunning)
            {
                long ticks = GetTimestamp() - _startTimeStamp;
                _elapsed += ticks;
                _isRunning = false;
            }
        }

        // Properties
        public TimeSpan Elapsed
        {
            get
            {
                return new TimeSpan(GetElapsedDateTimeTicks());
            }
        }

        public long ElapsedMilliseconds
        {
            get
            {
                return (GetElapsedDateTimeTicks() / 0x2710L);
            }
        }

        public long ElapsedTicks
        {
            get
            {
                return GetRawElapsedTicks();
            }
        }

        public bool IsRunning
        {
            get
            {
                return _isRunning;
            }
        }
    }
}
