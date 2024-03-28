using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace Client
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            //Example of using communicator
            /*const int PORT_NUM = 50001, MAX_AMOUNT_PACKET = 5;
            int amount_packets = 0;
            Communicator communicator = new Communicator(PORT_NUM);
            this.headline.Text = "Starting to listen";
            communicator.StartListening();
            while (amount_packets < MAX_AMOUNT_PACKET)
            {
                try
                {
                    AttackData data = communicator.GetMessageServer();
                    this.headline.Text = data.ToString();
                    amount_packets++;
                }
                catch(Exception excp) 
                {
                    this.headline.Text = excp.Message;
                }
            }
            communicator.StopListening();*/
        }
    }
}