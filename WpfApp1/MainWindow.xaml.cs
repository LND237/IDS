using System.Timers;
using System.Windows;
using MongoDB.Driver;

namespace WpfApp1
{
    public partial class MainWindow : Window
    {
        private MongoClient client;
        private System.Timers.Timer timer;

        public MainWindow()
        {
            InitializeComponent();

            // Replace with your actual Atlas connection string
            string connectionString = "mongodb+srv://<username>:<password>@<yourcluster>.mongodb.net/?retryWrites=true&w=majority";
            client = new MongoClient(connectionString);

            timer = new System.Timers.Timer(10000); // 10 seconds interval
            timer.Elapsed += OnTimerElapsed;
            timer.Start();
        }

        private async void OnTimerElapsed(object sender, ElapsedEventArgs e)
        {
            try
            {
                // For basic connectivity check, try listing databases
                var databases = await client.ListDatabasesAsync();
                Console.WriteLine("Connection successful!");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Connection failed: " + ex.Message);
            }
        }
    }
}
