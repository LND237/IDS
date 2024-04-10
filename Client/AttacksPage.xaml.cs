using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
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
    /// Interaction logic for AttacksPage.xaml
    /// </summary>
    public partial class AttacksPage : Page
    {
        private string IP;
        private string attacktype;
        private string startDate;
        private string endDate;
        public AttacksPage()
        {
            InitializeComponent();
        }

        private void ClearInputs()
        {
            SearchIPTextBox.Clear();
            attackTypeComboBox.SelectedIndex = -1;
            StartDate.Text = "";
            EndDate.Text = "";
        }
        private void Search_Button_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                this.IP = SearchIPTextBox.Text;
                this.attacktype = attackTypeComboBox.Text;
                this.startDate = StartDate.Text;
                this.endDate = EndDate.Text;
                if(this.startDate != "" && this.endDate != "")
                {

                    if(DateTime.Parse(startDate) > DateTime.Parse(endDate))
                    {
                        throw new Exception("START DATE NUST BE BEFORE END DATE!");
                    }
                }
            }
            catch(Exception ex)
            {
                MessageBox.Show(ex.Message, "Error!", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            ClearInputs();
        }
        
    }
}
