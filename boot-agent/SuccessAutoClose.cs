internal sealed class SuccessAutoClose
{
    private long? readyAtMilliseconds;

    public bool ShouldClose(long elapsedMilliseconds, bool ready)
    {
        if (!ready)
        {
            readyAtMilliseconds = null;
            return false;
        }
        if (!readyAtMilliseconds.HasValue) readyAtMilliseconds = elapsedMilliseconds;
        return elapsedMilliseconds - readyAtMilliseconds.Value >= 10000;
    }
}
