using System.Timers;
using System.Windows;
using MongoDB.Driver;
using WpfApp1.Models.MongoDB;
namespace WpfApp1
{
    public partial class MainWindow : Window
    {
        private MongoClient client;
        private System.Timers.Timer timer;

        public MainWindow()
        {
            
            InitializeComponent();

        }
    }
}
