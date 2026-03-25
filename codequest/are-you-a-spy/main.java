import java.util.Scanner;

public class main{
    public static void main(String[] args) {
        try (Scanner input = new Scanner(System.in)) {
            int testCases = Integer.parseInt(input.nextLine());
            for (int testcase = 0; testcase < testCases; testcase++) {
                String agent = input.nextLine();
                String person = agent.substring(agent.indexOf("|")+1).toLowerCase();
                agent = agent.substring(0,agent.indexOf("|")).toLowerCase();
                int count = 0;
                String[] alphabet = {"a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z"};
                for(int i = 0; i<person.length();i++){
                    String letter = String.valueOf(person.charAt(i));
                    for(int j = 0; j<alphabet.length; j++){
                        if(letter.equals(alphabet[j])){
                            count++;
                        }
                    }
                    if(count>0){
                       if(agent.indexOf(letter) == -1){
                        count++;
                       }
                       else{
                        count--;
                       }
                    }
                        
                } 
                if(count>0){
                    System.out.println("You're not a secret agent!");
                }
                else{
                    System.out.println("That's my secret agent!");
                }
            }
        }
    }
} 
