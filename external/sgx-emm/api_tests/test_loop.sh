let fail=0
for ((i=1;i<=$1;i++));do
    time ./test_mm_api
    if [ $? -eq 0 ]
    then
        echo "pass for iteration $i"
    else
        echo "fail for iteration $i"
        let fail=fail+1
    fi
done
if [ $fail -eq 0 ]
then
    echo "passed $1 iterations"
 else
    echo "$fail out of $1 iterations failed"
fi
