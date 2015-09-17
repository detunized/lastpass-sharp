namespace LastPass
{
    public class GenericNote : IEntry
    {
        public GenericNote(string id, string name, string contents)
        {
            Id = id;
            Name = name;
            Contents = contents;
        }

        public string Id { get; private set; }
        public string Name { get; private set; }
        public string Contents { get; private set; }
    }
}